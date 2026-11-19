"""Tests for the reporting-window logic in period_config.

These guard the date-boundary handling that every "current period" figure in
the pipeline depends on. They run without any downloaded data.
"""

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))


def _df(dates):
    return pd.DataFrame({"published": pd.to_datetime(dates, utc=True)})


def test_period_mask_includes_window_and_excludes_after():
    from period_config import period_mask

    df = _df(
        [
            "2026-01-01T00:00:00Z",  # first instant - in
            "2026-12-31T23:59:59Z",  # last instant of Dec 31 - in
            "2027-01-01T00:00:00Z",  # first instant of the next year - out
            "2025-12-31T23:59:59Z",  # prior year - out
        ]
    )
    mask = period_mask(df)
    assert list(mask) == [True, True, False, False]


def test_period_mask_handles_naive_dates():
    """Naive (tz-less) timestamps should still bin correctly (coerced to UTC)."""
    from period_config import period_mask

    df = pd.DataFrame({"published": pd.to_datetime(["2026-03-15", "2025-03-15"])})
    assert list(period_mask(df)) == [True, False]


def test_prior_period_mask_selects_prior_year_same_window():
    from period_config import prior_period_mask

    df = _df(["2025-03-15T00:00:00Z", "2026-03-15T00:00:00Z", "2025-12-31T23:00:00Z", "2024-12-31T23:00:00Z"])
    assert list(prior_period_mask(df)) == [True, False, True, False]


def test_same_elapsed_mask_respects_asof_day():
    from period_config import same_elapsed_mask

    asof = pd.Timestamp("2026-06-26", tz="UTC")
    df = _df(
        [
            "2025-06-26T12:00:00Z",  # on the as-of day - in
            "2025-06-27T00:00:00Z",  # day after as-of - out
            "2025-01-01T00:00:00Z",  # start - in
        ]
    )
    assert list(same_elapsed_mask(df, 2025, asof)) == [True, False, True]


def test_period_days_is_the_full_year():
    from period_config import PERIOD_DAYS

    # Jan 1 2026 -> Jan 1 2027 (exclusive); 2026 is not a leap year.
    assert PERIOD_DAYS == 365


def test_window_complete_only_on_the_last_day():
    from period_config import window_complete

    assert not window_complete(pd.Timestamp("2026-11-18T23:00:00Z"))
    assert not window_complete(pd.Timestamp("2026-12-30T23:59:59Z"))
    assert window_complete(pd.Timestamp("2026-12-31T00:05:00Z"))


def test_post_lives_where_the_series_expects():
    from period_config import POST_SLUG, POST_TITLE, POST_URL, PUBLISH_DATE

    assert POST_TITLE == "2026 CVE Data Review"
    assert PUBLISH_DATE == "2027-01-01"
    assert POST_URL == f"https://jerrygamblin.com/2027/01/01/{POST_SLUG}/"


def test_midyear_call_matches_the_published_post():
    """The annual post grades these numbers, so they must be the ones published."""
    from period_config import MIDYEAR_CALL

    assert MIDYEAR_CALL["my_call"] == 72008
    assert MIDYEAR_CALL["model_forecast"] == 90831
    assert MIDYEAR_CALL["url"].endswith("/2026/07/01/cve-mid-year-2026-check-in/")
