#!/usr/bin/env python3
"""
Central reporting-period configuration for the 2026 CVE Data Review.

Every current-period filter in the analysis scripts routes through ``period_mask``
/ ``prior_period_mask`` defined here, so the window is configured in exactly one
place. Run before the year closes, the pipeline produces a preview: every
comparison then uses the same Jan 1 to as-of window in earlier years
(``same_elapsed_mask``), so a partial year is never measured against a full one.
"""

import pandas as pd

# -----------------------------------------------------------------------------
# Reporting period: all of 2026 (Jan 1 - Dec 31, inclusive)
# -----------------------------------------------------------------------------
TARGET_YEAR = 2026
PRIOR_YEAR = 2025  # used for year-over-year comparisons

# Half-open interval [START, END): END is the first instant outside the window.
PERIOD_START = pd.Timestamp(f"{TARGET_YEAR}-01-01", tz="UTC")
PERIOD_END = pd.Timestamp(f"{TARGET_YEAR + 1}-01-01", tz="UTC")

# Human-readable labels used in chart titles and prose.
PERIOD_LABEL = f"{TARGET_YEAR}"  # short tag for chart titles and prose
PERIOD_TITLE = f"{TARGET_YEAR}"  # post / report title
PERIOD_RANGE = f"Jan 1 - Dec 31, {TARGET_YEAR}"

# Historical charts (CVEs-by-year, growth, data-quality) span this range.
# 2026 is included but is a PARTIAL year and must be labelled as such.
HIST_MIN_YEAR = 1999
HIST_MAX_YEAR = TARGET_YEAR

# Days in the reporting window (365 in 2026; 2026 is not a leap year).
PERIOD_DAYS = (PERIOD_END - PERIOD_START).days

# -----------------------------------------------------------------------------
# Where the post lives on jerrygamblin.com. 04_generate_blog.py uses these for
# the "Cite this analysis" block and the series links at the foot of the post,
# and 10_publish_wordpress.py uses them for the draft's slug, date and tags.
# The 2025 review went out on 2026-01-01 as /2026/01/01/2025-cve-data-review/.
# -----------------------------------------------------------------------------
SITE_URL = "https://jerrygamblin.com"
POST_TITLE = f"{PERIOD_TITLE} CVE Data Review"
POST_SLUG = f"{TARGET_YEAR}-cve-data-review"
# The permalink includes the date, so the citation URL is only right if the post
# goes out on this day. The publish script sets it on the draft for that reason.
PUBLISH_DATE = f"{TARGET_YEAR + 1}-01-01"
POST_URL = f"{SITE_URL}/{PUBLISH_DATE.replace('-', '/')}/{POST_SLUG}/"
# Tag slugs. They must already exist on the site; the publish script will not
# create tags.
POST_TAGS = ("cve", "cve-data-review")
# Where the pipeline lives, linked from the Methodology section. Create the
# GitHub repository before publishing or that link will 404.
REPO = "jgamblin/2026CVEBlog"
# Markdown line that links this post into the series. Once this post is live,
# the 2025 review needs a matching "The year after: ..." line added by hand.
SERIES_LINE = (
    "The year before: [2025 CVE Data Review]"
    "(https://jerrygamblin.com/2026/01/01/2025-cve-data-review/). "
    "The mid-year check-in: [CVE Mid-Year 2026 Check-In]"
    "(https://jerrygamblin.com/2026/07/01/cve-mid-year-2026-check-in/). "
    "All of my CVE analysis is on the [research page](https://jerrygamblin.com/research/)."
)

# The call made in the mid-year post, quoted from the published page: "My call
# is the year closes nearer 72,008 than 90,831", where 90,831 was CVEForecast's
# full-year projection (LinearRegression, MAPE 17.9). The annual post grades it.
MIDYEAR_CALL = {
    "url": "https://jerrygamblin.com/2026/07/01/cve-mid-year-2026-check-in/",
    "my_call": 72008,
    "model_forecast": 90831,
    "model": "LinearRegression",
    "model_mape": 17.9,
}


def _date_column(df):
    """Return the name of the publish-date column present on ``df`` (or None)."""
    for col in ("published", "date_published"):
        if col in df.columns:
            return col
    return None


def period_mask(df, start=PERIOD_START, end=PERIOD_END):
    """Boolean mask selecting rows published within [start, end).

    Falls back to the CVE ``year`` column when no publish-date column exists, so
    the helper is a drop-in replacement for the old ``df["year"] == YEAR`` filters
    regardless of which dataset (NVD or CVE List V5) is passed in.
    """
    col = _date_column(df)
    if col is None:
        if "year" in df.columns:
            return df["year"] == start.year
        raise KeyError("DataFrame has no publish-date or year column")
    dates = pd.to_datetime(df[col], utc=True, errors="coerce")
    return (dates >= start) & (dates < end)


def prior_period_mask(df):
    """Mask for the same Jan 1 - Dec 31 window in the prior year.

    Shifts both ends back by whole years. ``PERIOD_END.replace(year=PRIOR_YEAR)``
    would be wrong for a full year: PERIOD_END is Jan 1 of the NEXT year, so it
    would land on Jan 1 of the prior year and select nothing.
    """
    shift = pd.DateOffset(years=TARGET_YEAR - PRIOR_YEAR)
    return period_mask(df, start=PERIOD_START - shift, end=PERIOD_END - shift)


def filter_period(df):
    """Return a copy of ``df`` restricted to the reporting window."""
    return df[period_mask(df)].copy()


def current_asof(df):
    """Latest publish date present in the current reporting window.

    Used to measure every prior year over the identical elapsed window. Falls
    back to the day before the window closes if no dated rows are present.
    """
    cur = df[period_mask(df)]
    col = _date_column(cur)
    if col is None or len(cur) == 0:
        return PERIOD_END - pd.Timedelta(days=1)
    dates = pd.to_datetime(cur[col], utc=True, errors="coerce").dropna()
    return dates.max() if len(dates) else (PERIOD_END - pd.Timedelta(days=1))


def same_elapsed_mask(df, year, asof):
    """Mask for Jan 1 of ``year`` through the same month/day as ``asof``.

    Keeps year-over-year comparisons fair while the current period is still in
    progress: every year is measured over the identical number of elapsed days.
    Once the year closes (asof = Dec 31) this is the whole calendar year.
    """
    start = pd.Timestamp(f"{year}-01-01", tz="UTC")
    # Include the as-of day itself by ending at the following midnight.
    end = pd.Timestamp(f"{year}-{asof.month:02d}-{asof.day:02d}", tz="UTC") + pd.Timedelta(
        days=1
    )
    return period_mask(df, start=start, end=end)


def window_complete(asof):
    """True once ``asof`` reaches the last day of the reporting window.

    Before then the pipeline is producing a preview, and the prose says so.
    """
    last_day = (PERIOD_END - pd.Timedelta(days=1)).date()
    return pd.Timestamp(asof).date() >= last_day
