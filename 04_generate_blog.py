#!/usr/bin/env python3
"""
Generate the 2026 CVE Data Review Blog Post
Creates a publishable Markdown blog with all visualizations

This script imports graph generation functions from 03_generate_graphs.py
to avoid code duplication and ensure consistent styling.
"""

import pandas as pd
from pathlib import Path
from datetime import datetime
import warnings
import importlib.util

import json
import re
from urllib.parse import quote_plus, urlparse

from style_config import CWE_NAMES, prettify_name
from period_config import (
    period_mask,
    same_elapsed_mask,
    prior_period_mask,
    window_complete,
    current_asof,
    PERIOD_START,
    PERIOD_DAYS,
    PERIOD_LABEL,
    PERIOD_TITLE,
    TARGET_YEAR,
    PRIOR_YEAR,
    HIST_MIN_YEAR,
    SITE_URL,
    POST_TITLE,
    POST_URL,
    PUBLISH_DATE,
    SERIES_LINE,
    MIDYEAR_CALL,
    REPO,
)

warnings.filterwarnings("ignore")

# Directories
OUTPUT_DIR = Path("processed")
GRAPHS_DIR = Path("graphs")
GRAPHS_DIR.mkdir(exist_ok=True)

# Import graph generation functions - using importlib for numeric filename
spec = importlib.util.spec_from_file_location(
    "generate_graphs", "03_generate_graphs.py"
)
if spec is None or spec.loader is None:
    raise ImportError("Could not load 03_generate_graphs.py")
graphs_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(graphs_module)

# Re-export functions from graphs module for use in this script
graph_cves_by_year = graphs_module.graph_cves_by_year
graph_yoy_growth = graphs_module.graph_yoy_growth
graph_cumulative_growth = graphs_module.graph_cumulative_growth
graph_period_monthly = graphs_module.graph_period_monthly
graph_cvss_distribution = graphs_module.graph_cvss_distribution
graph_severity_breakdown = graphs_module.graph_severity_breakdown
graph_top_cwes = graphs_module.graph_top_cwes
graph_top_cnas = graphs_module.graph_top_cnas
graph_data_quality = graphs_module.graph_data_quality
graph_rejected_cves = graphs_module.graph_rejected_cves
graph_cvss_by_year = graphs_module.graph_cvss_by_year
graph_top_vendors = graphs_module.graph_top_vendors
graph_day_of_week = graphs_module.graph_day_of_week
graph_top_days = graphs_module.graph_top_days
graph_top_products = graphs_module.graph_top_products
graph_scorecard = graphs_module.graph_scorecard
normalize_data = graphs_module.normalize_data


# =============================================================================
# DATA LOADING
# =============================================================================
def load_data():
    """Load processed data, returning both filtered and full datasets"""
    print("Loading processed data...")

    nvd_df = None
    cvelist_df = None

    if (OUTPUT_DIR / "nvd_cves.parquet").exists():
        nvd_df = pd.read_parquet(OUTPUT_DIR / "nvd_cves.parquet")
        print(f"  ✓ Loaded NVD data: {len(nvd_df):,} CVEs")
    elif (OUTPUT_DIR / "nvd_cves.csv").exists():
        nvd_df = pd.read_csv(
            OUTPUT_DIR / "nvd_cves.csv", parse_dates=["published", "modified"]
        )
        print(f"  ✓ Loaded NVD data: {len(nvd_df):,} CVEs")

    if (OUTPUT_DIR / "cvelist_v5.parquet").exists():
        cvelist_df = pd.read_parquet(OUTPUT_DIR / "cvelist_v5.parquet")
        print(f"  ✓ Loaded CVE List V5 data: {len(cvelist_df):,} CVEs")
    elif (OUTPUT_DIR / "cvelist_v5.csv").exists():
        cvelist_df = pd.read_csv(
            OUTPUT_DIR / "cvelist_v5.csv",
            parse_dates=["date_reserved", "date_published"],
        )
        print(f"  ✓ Loaded CVE List V5 data: {len(cvelist_df):,} CVEs")

    # Keep full datasets for rejection analysis
    full_nvd_df = nvd_df.copy() if nvd_df is not None else None
    full_cvelist_df = cvelist_df.copy() if cvelist_df is not None else None

    # Filter out rejected CVEs for the main analysis
    if nvd_df is not None and "is_rejected" in nvd_df.columns:
        rejected_count = nvd_df["is_rejected"].sum()
        print(f"  → Filtering out {rejected_count:,} rejected CVEs from NVD data")
        nvd_df = nvd_df[~nvd_df["is_rejected"]].copy()

    if cvelist_df is not None and "is_rejected" in cvelist_df.columns:
        rejected_count = cvelist_df["is_rejected"].sum()
        print(f"  → Filtering out {rejected_count:,} rejected CVEs from CVE List V5")
        cvelist_df = cvelist_df[~cvelist_df["is_rejected"]].copy()

    # STRICT CUTOFF: exclude any data published after the target year so a
    # re-run on a later date never pulls future-dated CVEs into the totals.
    if nvd_df is not None and "year" in nvd_df.columns:
        future_count = (nvd_df["year"] > TARGET_YEAR).sum()
        if future_count > 0:
            print(
                f"  → Excluding {future_count:,} CVEs from after {TARGET_YEAR} (strict cutoff)"
            )
            nvd_df = nvd_df[nvd_df["year"] <= TARGET_YEAR].copy()

    if cvelist_df is not None and "year" in cvelist_df.columns:
        future_count = (cvelist_df["year"] > TARGET_YEAR).sum()
        if future_count > 0:
            print(
                f"  → Excluding {future_count:,} CVEs from after {TARGET_YEAR} (strict cutoff)"
            )
            cvelist_df = cvelist_df[cvelist_df["year"] <= TARGET_YEAR].copy()

    # Also apply cutoff to full datasets used for rejection analysis
    if full_nvd_df is not None and "year" in full_nvd_df.columns:
        full_nvd_df = full_nvd_df[full_nvd_df["year"] <= TARGET_YEAR].copy()

    if full_cvelist_df is not None and "year" in full_cvelist_df.columns:
        full_cvelist_df = full_cvelist_df[full_cvelist_df["year"] <= TARGET_YEAR].copy()

    # Return both filtered (active) and full datasets
    return nvd_df, cvelist_df, full_nvd_df, full_cvelist_df


# =============================================================================
# HELPERS
# =============================================================================
def _movers(cur_counts, prior_counts, topn=5):
    """Rank the top ``topn`` of ``cur_counts`` and tag movement vs prior period."""
    prior_rank = {name: i + 1 for i, name in enumerate(prior_counts.index)}
    out = []
    for i, (name, cnt) in enumerate(cur_counts.head(topn).items()):
        pr = prior_rank.get(name)
        cur_rank = i + 1
        if pr is None:
            status = "new"
        elif pr > cur_rank:
            status = "up"
        elif pr < cur_rank:
            status = "down"
        else:
            status = "flat"
        out.append(
            {"name": name, "count": int(cnt), "prior_rank": pr, "status": status}
        )
    return out


def cwe_link(cwe):
    """Markdown link from a CWE id to its MITRE definition page."""
    num = cwe.split("-")[1] if "-" in cwe else cwe
    return f"[{cwe}](https://cwe.mitre.org/data/definitions/{num}.html)"


# Public-facing display names for raw CNA assigner_short_name values. The raw
# catalog id (e.g. "GitHub_M") should never appear in reader-facing copy.
_CNA_DISPLAY = {
    "github_m": "GitHub Security Advisories",
}


def cna_display(name):
    """Human-friendly public name for a CNA short_name."""
    return _CNA_DISPLAY.get(str(name).lower(), str(name))


def pretty(name):
    """Human-friendly display of a normalized vendor/product slug."""
    return prettify_name(name)


_DAY_NAMES = {
    "Mon": "Monday",
    "Tue": "Tuesday",
    "Wed": "Wednesday",
    "Thu": "Thursday",
    "Fri": "Friday",
    "Sat": "Saturday",
    "Sun": "Sunday",
}


# Memory-safety weakness classes, for the CWE takeaway.
MEMORY_SAFETY_CWES = {
    "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-190",
    "CWE-416", "CWE-476", "CWE-787",
}


def _ranked(pairs, n, label=str):
    """'A 1,234, B 567' from (name, count) pairs, top ``n`` only."""
    return ", ".join(f"{label(k)} {int(v):,}" for k, v in list(pairs)[:n])


def _cwe_label(cwe):
    """Match the chart's y-axis label: 'CWE-79 (XSS)'."""
    return f"{cwe} ({CWE_NAMES[cwe]})" if cwe in CWE_NAMES else cwe


def chart_alt_text(
    stats,
    top_cwes,
    top_cnas,
    top_vendors,
    peak_month,
    peak_count,
    rejected_stats=None,
    day_stats=None,
    top_days=None,
    top_products=None,
):
    """Alt text for each chart in the post, keyed by file name.

    Each one says what the chart shows and the number that matters, taken from
    the same data the chart plots. Until November 2026 the alt text repeated the
    heading above the chart ("Top CNAs"), so a screen reader user got the label
    and none of the argument, and the charts in every review were rewritten by
    hand on the live site.

    CNAs use cna_display(), like the prose and tables, since alt text is read
    by people and the raw catalog id (GitHub_M) is not meant for them.
    04 writes this to graphs/alt_text.json, and 10_publish_wordpress.py sets it
    on each image when it uploads, so enrichment cannot lose it.
    """
    label = PERIOD_LABEL
    total = int(stats["total_2025"])
    alt = {
        "01_cves_by_year.png": (
            f"Bar chart of CVEs published each year since {HIST_MIN_YEAR}, "
            f"with {total:,} in {label}"
        ),
        "02_yoy_growth.png": (
            f"Bar chart of growth in published CVEs year over year, with {label} "
            f"{'up' if stats['yoy_change'] >= 0 else 'down'} {abs(stats['yoy_change']):.1f}% "
            f"on {PRIOR_YEAR}"
        ),
        "03_cumulative_growth.png": (
            f"Area chart of the cumulative CVE count since {HIST_MIN_YEAR}, which has "
            f"passed {int(stats['total_all_time']):,}"
        ),
        "05_cvss_distribution.png": (
            f"Histogram of CVSS scores for {label} CVEs, with an average of "
            f"{stats['avg_cvss']:.2f} and a median of {stats['median_cvss']:.2f}"
        ),
        "13_cvss_by_year.png": (
            f"Box plot of CVSS scores by year from 2018 through {label}, with a "
            f"median of {stats['median_cvss']:.2f} in {label}"
        ),
        "09_data_quality.png": (
            f"Bar chart of CVE data quality by year: in {label}, "
            f"{stats['cvss_coverage']:.1f}% of CVEs have a CVSS score, "
            f"{stats['cwe_coverage']:.1f}% a CWE and {stats['cpe_coverage']:.1f}% "
            f"CPE identifiers"
        ),
    }

    if peak_month and peak_count:
        month = datetime.strptime(peak_month, "%b").strftime("%B")
        alt["04_monthly.png"] = (
            f"Bar chart of CVEs published per month in {label}, peaking in "
            f"{month} at {int(peak_count):,}"
        )

    severities = [
        ("Critical", stats["critical"]),
        ("High", stats["high"]),
        ("Medium", stats["medium"]),
        ("Low", stats["low"]),
    ]
    unscored = total - sum(int(v) for _, v in severities)
    if unscored > 0:
        severities.append(("Unscored", unscored))
    alt["06_severity_breakdown.png"] = (
        f"Bar chart of {label} CVEs by severity: {_ranked(severities, 5)}"
    )

    if day_stats:
        peak_day = _DAY_NAMES.get(day_stats["peak_day"], day_stats["peak_day"])
        line = f"{peak_day} leads with {int(day_stats['peak_count']):,}"
        if peak_day != "Tuesday":
            line += f" and Tuesday has {int(day_stats['tuesday_count']):,}"
        alt["16_day_of_week.png"] = f"Bar chart of {label} CVEs by day of the week: {line}"

    if top_days:
        def _day(d):
            dt = datetime.strptime(d, "%Y-%m-%d")
            return f"{dt:%B} {dt.day}"

        busiest = [(_day(d), c) for d, c in top_days[:2]]
        alt["17_top_days.png"] = (
            f"Bar chart of the busiest days of {label}, led by "
            f"{busiest[0][0]} with {int(busiest[0][1]):,} CVEs"
            + (f" and {busiest[1][0]} with {int(busiest[1][1]):,}" if len(busiest) > 1 else "")
        )

    if top_cwes:
        alt["07_top_cwes.png"] = (
            f"Bar chart of the most common CWEs in {label}: "
            f"{_ranked(top_cwes, 3, _cwe_label)}"
        )
    if top_cnas:
        alt["08_top_cnas.png"] = (
            f"Bar chart of the CNAs that assigned the most CVEs in {label}: "
            f"{_ranked(top_cnas, 5, cna_display)}"
        )
    if top_vendors:
        alt["14_top_vendors.png"] = (
            f"Bar chart of the vendors with the most CVEs in {label}: "
            f"{_ranked(top_vendors, 5, pretty)}"
        )
    if top_products:
        alt["18_top_products.png"] = (
            f"Bar chart of the products with the most CVEs in {label}: "
            f"{_ranked(top_products, 5, pretty)}"
        )
    if rejected_stats:
        alt["10_rejected_cves.png"] = (
            f"Two charts of rejected CVEs by year, as a count and as a rate: "
            f"{int(rejected_stats['rejected_2025']):,} in {label}, a "
            f"{rejected_stats['rate_2025']:.2f}% rejection rate"
        )

    # Square brackets would break the Markdown image syntax.
    return {k: v.replace("[", "(").replace("]", ")") for k, v in alt.items()}


def vendor_link(vendor):
    """Markdown link from a vendor to its NVD advanced-search results."""
    slug = quote_plus(str(vendor).lower().strip())
    base = (
        "https://nvd.nist.gov/vuln/search/results?form_type=Advanced"
        "&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor="
    )
    return f"[{pretty(vendor)}]({base}{slug})"


# Known first-party sub-CNAs: CNA short name -> parent vendor it assigns for.
_FIRST_PARTY_CNA = {
    "chrome": "google",
    "android": "google",
    "github_m": "github",
}


def _is_self_assigned(cna, name):
    """True when the dominant CNA looks like the vendor/product itself."""
    a = re.sub(r"[^a-z0-9]", "", str(cna).lower())
    b = re.sub(r"[^a-z0-9]", "", str(name).lower())
    if not a or not b:
        return False
    if a in b or b in a:
        return True
    parent = _FIRST_PARTY_CNA.get(str(cna).lower())
    return bool(parent and re.sub(r"[^a-z0-9]", "", parent) in b)


def cna_concentration(cvelist_df, asof, top_n=15, threshold=0.6, fields=("vendor",)):
    """Flag report callouts dominated by a single THIRD-PARTY CNA.

    When one CNA that is not the vendor itself assigns most of a vendor's CVEs
    (as VulnCheck did for OpenClaw), a "top vendor" callout can reflect one
    researcher group's disclosure push rather than broad activity. Self-assigned
    dominance (the Linux CNA for Linux, Chrome for Google, etc.) is expected and
    skipped. Defaults to vendors only; product names rarely match their owning
    CNA textually, so checking them is noisy. Returns the flagged items.
    """
    flagged = []
    if cvelist_df is None or "assigner_short_name" not in cvelist_df.columns:
        return flagged

    cur = cvelist_df[same_elapsed_mask(cvelist_df, TARGET_YEAR, asof)]
    exclude = {"n/a", "unknown", "none", "na", "n_a", "*", ""}
    for field in fields:
        if field not in cur.columns:
            continue
        sub = cur[cur[field].notna()].copy()
        sub["_key"] = sub[field].astype(str).str.lower().str.strip()
        sub = sub[~sub["_key"].isin(exclude)]
        for name, total in sub["_key"].value_counts().head(top_n).items():
            ac = sub[sub["_key"] == name]["assigner_short_name"].value_counts()
            if ac.empty:
                continue
            top_cna, top_ct = str(ac.index[0]), int(ac.iloc[0])
            share = top_ct / total
            if share >= threshold and not _is_self_assigned(top_cna, name):
                flagged.append(
                    {
                        "type": field,
                        "name": name,
                        "total": int(total),
                        "top_cna": top_cna,
                        "top_cna_count": top_ct,
                        "share": round(share * 100, 1),
                    }
                )

    if flagged:
        print("\n" + "!" * 64)
        print("CNA CONCENTRATION WARNING: callouts dominated by one third-party CNA")
        print("!" * 64)
        for f in sorted(flagged, key=lambda x: -x["share"]):
            print(
                f"  {f['type']:7} {f['name'][:26]:26} {f['total']:>5} CVEs  "
                f"{f['share']:>5.1f}% from {f['top_cna']}"
            )
        print(
            "Review before publishing: a spotlight on any of these reflects one "
            "group's disclosure push, not broad activity.\n"
        )
    return flagged


# =============================================================================
# STATISTICS CALCULATION
# =============================================================================
def calculate_stats(df, cvelist_df, full_nvd_df=None, full_cvelist_df=None):
    """Calculate all statistics for the blog"""
    stats = {}

    df_2025 = df[period_mask(df)].copy()  # current period, to the as-of date

    # As-of date = latest publish date in the current window. Year-over-year
    # comparisons use the SAME elapsed window in prior years, so a partial year
    # is never measured against a full one. Once the year closes (Dec 31) the
    # same-elapsed window is the whole calendar year.
    pubs = pd.to_datetime(df_2025["published"], utc=True, errors="coerce").dropna()
    asof = pubs.max() if len(pubs) else PERIOD_START
    stats["asof"] = asof
    stats["asof_label"] = f"{asof:%b} {asof.day}"
    stats["window_complete"] = window_complete(asof)

    df_2024 = df[same_elapsed_mask(df, PRIOR_YEAR, asof)]  # same window, prior year

    stats["total_2025"] = len(df_2025)
    stats["total_2024"] = len(df_2024)
    stats["total_all_time"] = len(df)
    stats["yoy_change"] = (
        ((stats["total_2025"] - stats["total_2024"]) / stats["total_2024"] * 100)
        if stats["total_2024"] > 0
        else 0
    )

    # Per-day pace + two straight-line full-year projections. They only matter
    # in a preview run, before the year closes.
    span_days = max((asof - PERIOD_START).days + 1, 1)
    stats["days_elapsed"] = span_days
    stats["cves_per_day"] = len(df_2025) / span_days if span_days else 0
    stats["projected_runrate"] = round(stats["cves_per_day"] * PERIOD_DAYS)
    # Seasonality-adjusted: divide by the share of the prior year's CVEs that had
    # published by the same day (CVE publishing is not evenly spread).
    full_prior = int(prior_period_mask(df).sum())
    prior_by_asof = int(same_elapsed_mask(df, PRIOR_YEAR, asof).sum())
    share = (prior_by_asof / full_prior) if full_prior else 1
    stats["prior_share_by_asof"] = share * 100
    stats["projected_seasonal"] = round(len(df_2025) / share) if share else 0
    stats["projected_full_year"] = stats["projected_runrate"]  # back-compat

    # Human-scale framings for the lead.
    stats["minutes_between"] = (1440 / stats["cves_per_day"]) if stats["cves_per_day"] else 0
    # The latest year X such that this period's count beats EVERY full year
    # before X, so "more than any full year before X" is true as written. The
    # old check took the most recent smaller year, which an earlier, larger year
    # could contradict.
    fy = df.groupby("year").size()
    stats["exceeds_year"] = None
    stats["exceeds_year_total"] = 0
    for x in range(TARGET_YEAR, HIST_MIN_YEAR, -1):
        before = [int(fy.get(y, 0)) for y in range(HIST_MIN_YEAR, x)]
        if before and stats["total_2025"] > max(before):
            stats["exceeds_year"] = x - 1
            stats["exceeds_year_total"] = int(fy.get(x - 1, 0))
            break
    # A record means more than every earlier year over the same elapsed window,
    # which once the year closes is simply the most CVEs in any calendar year.
    earlier = [
        int(same_elapsed_mask(df, y, asof).sum()) for y in range(HIST_MIN_YEAR, TARGET_YEAR)
    ]
    stats["is_record"] = bool(earlier) and stats["total_2025"] > max(earlier)

    # Three years side by side, identical elapsed window each.
    cvss_col0 = "cvss_v3" if "cvss_v3" in df.columns else "cvss_v4"
    compare = []
    for y in (TARGET_YEAR - 2, TARGET_YEAR - 1, TARGET_YEAR):
        d = df[same_elapsed_mask(df, y, asof)]
        compare.append(
            {
                "year": y,
                "total": len(d),
                "per_day": len(d) / span_days if span_days else 0,
                "avg_cvss": d[cvss_col0].mean()
                if cvss_col0 in d.columns and len(d)
                else 0,
            }
        )
    stats["compare"] = compare

    # Rejected CVE statistics (from full datasets)
    stats["rejected_2025"] = 0
    stats["rejected_all_time"] = 0
    if full_nvd_df is not None and "is_rejected" in full_nvd_df.columns:
        stats["rejected_all_time"] = full_nvd_df["is_rejected"].sum()
        stats["rejected_2025"] = full_nvd_df[
            (period_mask(full_nvd_df)) & (full_nvd_df["is_rejected"])
        ].shape[0]
    elif full_cvelist_df is not None and "is_rejected" in full_cvelist_df.columns:
        stats["rejected_all_time"] = full_cvelist_df["is_rejected"].sum()
        stats["rejected_2025"] = full_cvelist_df[
            (period_mask(full_cvelist_df)) & (full_cvelist_df["is_rejected"])
        ].shape[0]

    # Calculate rejection rate
    total_with_rejected_2025 = stats["total_2025"] + stats["rejected_2025"]
    stats["rejection_rate_2025"] = (
        (stats["rejected_2025"] / total_with_rejected_2025 * 100)
        if total_with_rejected_2025 > 0
        else 0
    )

    # Severity
    if "severity" in df_2025.columns:
        severity_counts = df_2025["severity"].str.upper().value_counts()
        stats["critical"] = severity_counts.get("CRITICAL", 0)
        stats["high"] = severity_counts.get("HIGH", 0)
        stats["medium"] = severity_counts.get("MEDIUM", 0)
        stats["low"] = severity_counts.get("LOW", 0)
    else:
        stats["critical"] = stats["high"] = stats["medium"] = stats["low"] = 0

    # CVSS
    cvss_col = "cvss_v3" if "cvss_v3" in df.columns else "cvss_v4"
    if cvss_col in df_2025.columns:
        stats["avg_cvss"] = df_2025[cvss_col].mean()
        stats["median_cvss"] = df_2025[cvss_col].median()
        stats["cvss_coverage"] = df_2025[cvss_col].notna().sum() / len(df_2025) * 100
    else:
        stats["avg_cvss"] = stats["median_cvss"] = stats["cvss_coverage"] = 0

    # CWE
    if "cwe" in df_2025.columns:
        stats["cwe_coverage"] = df_2025["cwe"].notna().sum() / len(df_2025) * 100
        stats["top_cwe"] = (
            df_2025["cwe"].value_counts().index[0]
            if df_2025["cwe"].notna().any()
            else "N/A"
        )
        stats["top_cwe_count"] = (
            df_2025["cwe"].value_counts().iloc[0] if df_2025["cwe"].notna().any() else 0
        )
    else:
        stats["cwe_coverage"] = 0
        stats["top_cwe"] = "N/A"
        stats["top_cwe_count"] = 0

    # CPE
    if "has_cpe" in df_2025.columns:
        stats["cpe_coverage"] = df_2025["has_cpe"].sum() / len(df_2025) * 100
    else:
        stats["cpe_coverage"] = 0

    # Yearly data
    yearly = df.groupby("year").size().reset_index(name="count")
    yearly = yearly[
        (yearly["year"] >= HIST_MIN_YEAR) & (yearly["year"] <= TARGET_YEAR)
    ]
    stats["yearly"] = yearly

    # CVE List V5 specific stats
    if cvelist_df is not None:
        cv_2025 = cvelist_df[period_mask(cvelist_df)]

        if "assigner_short_name" in cv_2025.columns:
            stats["unique_cnas"] = cv_2025["assigner_short_name"].nunique()
            cna_counts = cv_2025["assigner_short_name"].value_counts()
            stats["top_cna"] = cna_counts.index[0] if len(cna_counts) > 0 else "N/A"
            stats["top_cna_count"] = cna_counts.iloc[0] if len(cna_counts) > 0 else 0

        if "state" in cv_2025.columns:
            state_counts = cv_2025["state"].value_counts()
            stats["published"] = state_counts.get("PUBLISHED", 0)
            stats["rejected"] = state_counts.get("REJECTED", 0)
            stats["reserved"] = state_counts.get("RESERVED", 0)

        if "vendor" in cv_2025.columns:
            stats["unique_vendors"] = cv_2025["vendor"].nunique()

    # ----- "What changed" movers vs the same window a year ago -----------------
    asof = stats["asof"]

    if cvelist_df is not None and "assigner_short_name" in cvelist_df.columns:
        cur = cvelist_df[same_elapsed_mask(cvelist_df, TARGET_YEAR, asof)][
            "assigner_short_name"
        ].value_counts()
        pri = cvelist_df[same_elapsed_mask(cvelist_df, PRIOR_YEAR, asof)][
            "assigner_short_name"
        ].value_counts()
        stats["cna_movers"] = _movers(cur, pri, 5)

    if "product" in df.columns:
        cur_p = df[same_elapsed_mask(df, TARGET_YEAR, asof) & df["product"].notna()][
            "product"
        ].value_counts().head(8)
        pri_p = set(
            df[same_elapsed_mask(df, PRIOR_YEAR, asof) & df["product"].notna()][
                "product"
            ].value_counts().head(8).index
        )
        stats["new_products"] = [p for p in cur_p.index if p not in pri_p][:4]

    if "cwe" in df.columns:
        cur_c = df[same_elapsed_mask(df, TARGET_YEAR, asof) & df["cwe"].notna()][
            "cwe"
        ].value_counts()
        pri_c = df[same_elapsed_mask(df, PRIOR_YEAR, asof) & df["cwe"].notna()][
            "cwe"
        ].value_counts()
        stats["cwe_movers"] = _movers(cur_c, pri_c, 5)

    # OpenClaw assigner breakdown: who actually issued these CVEs (third-party
    # researchers vs the project itself). This is the story behind the count.
    if cvelist_df is not None and "vendor" in cvelist_df.columns:
        ocv = cvelist_df[same_elapsed_mask(cvelist_df, TARGET_YEAR, asof)]
        ocv = ocv[ocv["vendor"].astype(str).str.lower().str.strip() == "openclaw"]
        if len(ocv) and "assigner_short_name" in ocv.columns:
            ac = ocv["assigner_short_name"].value_counts()
            stats["openclaw"] = {
                "total": int(len(ocv)),
                "top_assigner": str(ac.index[0]),
                "top_assigner_count": int(ac.iloc[0]),
            }

    return stats


def midyear_verdict(total):
    """One paragraph grading the mid-year call against the year's final count.

    The mid-year post said the year would close nearer MIDYEAR_CALL["my_call"]
    than CVEForecast's MIDYEAR_CALL["model_forecast"]. Every outcome gets its
    own wording, including both numbers being low, so the post never claims
    more than the data shows.
    """
    my_call = MIDYEAR_CALL["my_call"]
    model_call = MIDYEAR_CALL["model_forecast"]
    d_me, d_model = abs(total - my_call), abs(total - model_call)
    if total >= model_call:
        verdict = (
            f"My model and I were both low, and I was further off: the year finished "
            f"{total - model_call:,} above the model's number and {total - my_call:,} "
            "above mine. The second-half surge I put the burden of proof on arrived, "
            "and then some."
        )
    elif d_me < d_model and total <= my_call:
        verdict = (
            f"My number was closer, and still too high: the year finished "
            f"{my_call - total:,} below it. The second-half surge the model needed "
            "did not come."
        )
    elif d_me < d_model:
        verdict = (
            f"My number was closer, by {d_model - d_me:,}, but the year still finished "
            f"{total - my_call:,} above it, so the second half did pick up, though not "
            "by as much as the model expected."
        )
    elif d_model < d_me:
        verdict = (
            f"The model was closer, and I was wrong: the year finished {d_me:,} away "
            f"from my number and {d_model:,} from the model's. The second half "
            "accelerated the way the forecast expected, and the burden of proof I put "
            "on the surge was met."
        )
    else:
        verdict = (
            "It landed exactly halfway between the two, so neither of us gets to claim it."
        )
    return verdict


# =============================================================================
# BLOG GENERATION
# =============================================================================
def generate_blog(
    stats,
    top_cwes,
    top_cnas,
    top_vendors,
    peak_month,
    peak_count,
    cumulative_total,
    rejected_stats=None,
    day_stats=None,
    top_days=None,
    top_products=None,
    forecast=None,
    kev=None,
    alt_text=None,
):
    """Generate the Markdown blog post"""

    # Dynamic date - use current date
    current_date = datetime.now().strftime("%B %d, %Y")

    alt = alt_text or chart_alt_text(
        stats,
        top_cwes,
        top_cnas,
        top_vendors,
        peak_month,
        peak_count,
        rejected_stats,
        day_stats,
        top_days,
        top_products,
    )

    def img(name):
        """Markdown for one chart, with alt text that says what it shows."""
        return f"![{alt[name]}](graphs/{name})"

    # Precomputed framing helpers
    kev = kev or {}
    label = PERIOD_LABEL
    asof_label = stats.get("asof_label", "Dec 31")
    complete = stats.get("window_complete", False)
    total = stats["total_2025"]
    prior_total = stats["total_2024"]
    yoy = stats["yoy_change"]
    up_down = "up" if yoy >= 0 else "down"
    # Before December 31 every comparison is over the same elapsed window.
    same_window = "" if complete else f" over the same January 1 to {asof_label} window"
    proj_lo = min(stats["projected_runrate"], stats["projected_seasonal"])
    proj_hi = max(stats["projected_runrate"], stats["projected_seasonal"])
    is_record = stats.get("is_record", False)
    cpe = stats["cpe_coverage"]
    kev_in = kev.get("h1_published_in_kev")
    kev_pct = (kev_in / max(total, 1) * 100) if kev_in is not None else None

    if complete:
        opening = (
            f"{label} set a new record with **{total:,}** published CVEs."
            if is_record
            else f"{label} closed with **{total:,}** published CVEs."
        )
        opening += (
            " This review covers everything published from January 1 to December 31: the "
            "volume, the severity, what is actually being exploited, who is driving the "
            "numbers, and how my mid-year call held up."
        )
        lead = (
            f"**{label} produced {total:,} CVEs, {up_down} {abs(yoy):.1f}% on "
            f"{PRIOR_YEAR} ({prior_total:,}).**"
        )
        if is_record:
            lead += " No year since the program began in 1999 has produced more."
        pace = (
            f"The all-time catalog now holds **{stats['total_all_time']:,} CVEs** "
            "published since 1999."
        )
    else:
        opening = (
            f"This is a preview of the {label} review, built from data through {asof_label}. "
            f"Every comparison uses the same January 1 to {asof_label} window in earlier "
            "years, so a partial year is never measured against a full one. The numbers will "
            "move before December 31, so treat them as a floor."
        )
        lead = (
            f"**Through {asof_label}, {label} has produced {total:,} CVEs, {up_down} "
            f"{abs(yoy):.1f}% on the same window of {PRIOR_YEAR} ({prior_total:,}).**"
        )
        exceeds_year = stats.get("exceeds_year")
        if exceeds_year:
            lead += (
                f" No full year before {exceeds_year + 1} produced as many: all of "
                f"{exceeds_year} finished at {stats['exceeds_year_total']:,}."
            )
        pace = (
            f"At this pace the year lands near **{proj_lo:,} to {proj_hi:,}**, and the "
            f"all-time catalog has passed **{stats['total_all_time']:,} CVEs** since 1999."
        )
    lead += f" That works out to one new CVE every **{stats['minutes_between']:.1f} minutes**."
    if kev_pct is not None:
        lead += (
            f" Only **{kev_in} of them ({kev_pct:.2f}%)** have made CISA's KEV list so far, "
            "a floor that will rise as the cohort ages and exploitation is confirmed. "
        )
        lead += (
            "That gap is the story of the year: volume keeps setting records while confirmed "
            "exploitation stays rare, so the hard problem is signal-to-noise, not patch volume."
            if is_record
            else "That gap is the story of the year: confirmed exploitation stays rare next to "
            "the volume, so the hard problem is signal-to-noise, not patch volume."
        )

    # Severity percentages, guarded against an empty current period so a
    # bad/partial data load degrades to 0% instead of a ZeroDivisionError.
    _tot = max(total, 1)
    sev_pct = {
        k: stats[k] / _tot * 100 for k in ("critical", "high", "medium", "low")
    }
    crit_high_pct = (stats["critical"] + stats["high"]) / _tot * 100
    # CVEs with no CVSS severity, so the percentage column sums to 100.
    _sev_sum = stats["critical"] + stats["high"] + stats["medium"] + stats["low"]
    sev_unscored = max(total - _sev_sum, 0)
    sev_pct["unscored"] = sev_unscored / _tot * 100

    blog = f"""# {POST_TITLE}

<!-- Featured image suggestion: graphs/00_scorecard.png (year-in-review stat card) -->

{opening}

## TL;DR

{lead}

{pace}

> **Note**: All statistics in this report exclude rejected CVEs to provide an accurate count of active vulnerabilities.

### Key Statistics at a Glance

| Metric | Value |
|--------|-------|
| **Total CVEs ({label})** | **{total:,}** |
| CVEs per Day | {stats["cves_per_day"]:.1f} |
| Change vs {PRIOR_YEAR}{"" if complete else " (same window)"} | {yoy:+.1f}% |
"""
    if not complete:
        blog += f"| Projected Full Year | {proj_lo:,} - {proj_hi:,} |\n"
    blog += f"""| Critical Severity | {stats["critical"]:,} |
| High Severity | {stats["high"]:,} |
| Average CVSS Score | {stats["avg_cvss"]:.2f} |
| CVSS Coverage | {stats["cvss_coverage"]:.1f}% |
| CWE Coverage | {stats["cwe_coverage"]:.1f}% |
"""

    if "unique_cnas" in stats:
        blog += f"| Active CNAs | {stats['unique_cnas']:,} |\n"

    if stats.get("rejected_2025", 0) > 0:
        blog += f"| Rejected CVEs ({label}) | {stats['rejected_2025']:,} |\n"

    if kev_in is not None:
        blog += f"| Already Known-Exploited (KEV) | {kev_in} |\n"

    # Three years side by side, identical elapsed window each.
    cmp_rows = ""
    for c in stats.get("compare", []):
        if complete:
            window = f"{c['year']}"
        else:
            tag = " *(partial)*" if c["year"] == TARGET_YEAR else ""
            window = f"Jan 1 - {asof_label}, {c['year']}{tag}"
        cmp_rows += (
            f"| {window} | {c['total']:,} | {c['per_day']:.1f} | {c['avg_cvss']:.2f} |\n"
        )
    cmp_intro = (
        "Each year is counted from January 1 to December 31."
        if complete
        else (
            f"To keep the comparison honest while {label} is still open, each year is "
            f"measured over the identical window (January 1 through {asof_label})."
        )
    )

    # Grade the call from the mid-year post, or track it while the year is open.
    call = MIDYEAR_CALL
    my_call, model_call = call["my_call"], call["model_forecast"]
    if complete:
        verdict = midyear_verdict(total)
        forecast_section = f"""## Scoring My Mid-Year Call

In my [mid-year check-in]({call["url"]}) I wrote that the year would close nearer **{my_call:,}** than the **{model_call:,}** my own [CVEForecast](https://cveforecast.org) model projected ({call["model"]}, MAPE {call["model_mape"]}). It closed at **{total:,}**.

{verdict}"""
    else:
        midpoint = (my_call + model_call) / 2
        settles = "The January review settles it."
        if proj_lo > model_call:
            tracking = (
                f"Both projections are already above even the model's {model_call:,}, "
                "so my call is not going to hold."
            )
            settles = "The January review puts a number on how far off I was."
        elif proj_hi < midpoint:
            tracking = "Both projections currently sit closer to my number."
        elif proj_lo > midpoint:
            tracking = "Both projections currently sit closer to the model's."
        else:
            tracking = "The two projections currently split the difference."
        model_now = ""
        if forecast and forecast.get("full_year_forecast"):
            model_now = f" CVEForecast now projects **{forecast['full_year_forecast']:,}**."
        forecast_section = f"""## Scorecard: On Pace for What?

At **{stats["cves_per_day"]:.1f} CVEs/day** through {asof_label}, the run-rate extrapolates to **{stats["projected_runrate"]:,}**, and dividing by the share of {PRIOR_YEAR}'s CVEs that had published by the same day ({stats["prior_share_by_asof"]:.0f}%) gives **{stats["projected_seasonal"]:,}**.

In my [mid-year check-in]({call["url"]}) I called the year closing nearer **{my_call:,}** than CVEForecast's **{model_call:,}**. {tracking}{model_now} {settles}"""

    # "What changed" callouts vs the same window a year ago.
    changed_bits = []
    movers = stats.get("cna_movers", [])
    new_cnas = [cna_display(m["name"]) for m in movers if m["status"] == "new"]
    if movers:
        leader = movers[0]
        lead_txt = (
            f"**{cna_display(leader['name'])}** is the busiest CNA at "
            f"**{leader['count']:,}** assignments"
        )
        if new_cnas:
            joined = ", ".join(new_cnas)
            verb = "is" if len(new_cnas) == 1 else "are"
            lead_txt += f", and {joined} {verb} new to the top five"
        changed_bits.append(lead_txt + ".")
    if stats.get("new_products"):
        nps = ", ".join(pretty(p) for p in stats["new_products"])
        changed_bits.append(f"New to the most-affected product list this year: **{nps}**.")
    for idx, m in enumerate(stats.get("cwe_movers", [])):
        if m["status"] in ("new", "up"):
            nm = CWE_NAMES.get(m["name"], m["name"])
            verb = "is new to" if m["status"] == "new" else f"climbed to #{idx + 1} in"
            changed_bits.append(
                f"Among weakness types, {cwe_link(m['name'])} ({nm}) {verb} the top five."
            )
            break
    # Editorial spotlight: OpenClaw, where most CVEs come from third-party
    # researchers rather than the project itself. Review before publishing.
    openclaw_spotlight = ""
    oc = stats.get("openclaw")
    if oc and oc.get("total"):
        share = oc["top_assigner_count"] / max(oc["total"], 1) * 100
        top_assigner = cna_display(oc["top_assigner"])
        was = "was" if complete else "is"
        openclaw_spotlight = (
            "\n\n**Spotlight: OpenClaw.** OpenClaw (Peter Steinberger's viral local AI agent, "
            "the subject of [Lex Fridman Podcast #491](https://www.youtube.com/watch?v=YFjfBk8HI5o)) "
            f"{was} one of the most-reported products of {label} with **{oc['total']:,} CVEs**. "
            f"The striking part is who did the reporting: **{top_assigner} alone assigned "
            f"{oc['top_assigner_count']:,}** of them ({share:.0f}%). That concentration says "
            f"more about researcher attention than code quality: {top_assigner}, whose remit is "
            "emerging and exploited-in-the-wild threats, is exactly the kind of team that "
            "systematically covers a fast-growing new target. To its credit the project "
            "embraced the CVE lifecycle itself, issuing advisories through GitHub as reports "
            "came in. I track its CVEs at [OpenClawCVEs](https://github.com/jgamblin/OpenClawCVEs)."
        )

    if changed_bits or openclaw_spotlight:
        changed_section = (
            f"## What Changed in {label}\n\n"
            + " ".join(changed_bits)
            + openclaw_spotlight
            + "\n\n---\n\n"
        )
    else:
        changed_section = ""

    if complete:
        growth_intro = f"Every year since {HIST_MIN_YEAR}, counted by publish date."
        if is_record:
            growth_intro += f" {label} is the tallest bar on the chart."
    else:
        growth_intro = (
            f"To compare like with like while {label} is still open, this chart counts each "
            f"year from January 1 through {asof_label}."
        )
        if is_record:
            growth_intro += f" On that basis {label} already stands taller than any earlier year."

    blog += f"""
---

## Three Years Side by Side

{cmp_intro}

| {"Year" if complete else "Window"} | CVEs | Per Day | Avg CVSS |
|--------|------|---------|----------|
{cmp_rows}
---

{forecast_section}

---

{changed_section}## Historical CVE Growth

{growth_intro}

{img("01_cves_by_year.png")}

Year over year, {label} is **{yoy:+.1f}%** on {PRIOR_YEAR}{same_window}.

{img("02_yoy_growth.png")}

Counting full years, the cumulative catalog has now passed **{stats["total_all_time"]:,} CVEs**.

{img("03_cumulative_growth.png")}

---

## Monthly Distribution

"""

    if peak_month and peak_count:
        peak_month_full = datetime.strptime(peak_month, "%b").strftime("%B")
        blog += f"""Publishing varied across {label}, with **{peak_month_full}** the peak month at **{peak_count:,} CVEs**.

{img("04_monthly.png")}

---
"""

    # Day of Week Analysis - drive the framing from the actual peak day.
    if day_stats:
        peak_day = _DAY_NAMES.get(day_stats["peak_day"], day_stats["peak_day"])
        peak_dc = day_stats["peak_count"]
        tue = day_stats["tuesday_count"]
        if str(peak_day).lower().startswith("tue"):
            day_line = (
                f"The Patch Tuesday effect is clear: **Tuesday** leads at "
                f"**{peak_dc:,} CVEs**, well above the weekday average."
            )
        else:
            day_line = (
                f"Publishing clusters midweek. **{peak_day}** is the busiest day at "
                f"**{peak_dc:,} CVEs**, with Tuesday close behind at **{tue:,}**. Patch "
                f"Tuesday is part of the story, but the midweek bulge owes as much to the "
                f"high-volume CNAs (GitHub, Linux, the WordPress plugin crowd) that "
                f"batch-publish midweek."
            )
        blog += f"""
## Publication Patterns by Day of Week

{day_line}

{img("16_day_of_week.png")}

Weekdays average **{day_stats["weekday_avg"]:,.0f}** CVEs against just **{day_stats["weekend_avg"]:,.0f}** on weekends.

---
"""

    # Top Days
    if top_days and len(top_days) > 0:
        blog += f"""
## Busiest Days of {label}

Some days saw massive spikes in CVE publications:

{img("17_top_days.png")}

### Top 5 Busiest Days

| Rank | Date | CVE Count |
|------|------|----------|
"""
        for i, (date, count) in enumerate(top_days[:5], 1):
            blog += f"| {i} | {date} | {count:,} |\n"
        blog += "\n---\n"

    blog += f"""
## CVSS Score Analysis

The Common Vulnerability Scoring System (CVSS) helps standardize severity assessments. Here's how {label} CVEs were distributed across the scoring range.

{img("05_cvss_distribution.png")}

The **average CVSS score for {label} was {stats["avg_cvss"]:.2f}**, with a **median of {stats["median_cvss"]:.2f}**.

### Severity Breakdown

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | {stats["critical"]:,} | {sev_pct["critical"]:.1f}% |
| High | {stats["high"]:,} | {sev_pct["high"]:.1f}% |
| Medium | {stats["medium"]:,} | {sev_pct["medium"]:.1f}% |
| Low | {stats["low"]:,} | {sev_pct["low"]:.1f}% |
| Unscored | {sev_unscored:,} | {sev_pct["unscored"]:.1f}% |

Percentages are of all {label} CVEs; "Unscored" are the {sev_pct["unscored"]:.1f}% with no CVSS severity assigned.

{img("06_severity_breakdown.png")}

### CVSS Trends Over Time

{img("13_cvss_by_year.png")}

---

## Top Weakness Types (CWE)

The Common Weakness Enumeration (CWE) categorizes the types of security weaknesses. Here are the most prevalent weakness types in {label}:

{img("07_top_cwes.png")}

### Top 5 CWEs in {label}

| Rank | CWE | Name | Count |
|------|-----|------|-------|
"""

    for i, (cwe, count) in enumerate(top_cwes, 1):
        name = CWE_NAMES.get(cwe, "")
        blog += f"| {i} | {cwe_link(cwe)} | {name} | {count:,} |\n"

    blog += f"""
---

## CVE Numbering Authorities (CNAs)

The leaderboard increasingly reflects where modern software and modern vulnerability research live: platform and ecosystem CNAs (GitHub, Patchstack) and dedicated research CNAs (VulnCheck, VulDB) alongside the traditional product vendors. High assignment counts are not inflation, a CNA covering the WordPress plugin ecosystem or issuing a CVE per kernel fix is doing exactly its job; the low KEV overlap below reflects how rare confirmed exploitation is across all sources, not the validity of any CNA's records. The most active assigners this year:

{img("08_top_cnas.png")}

### Top 5 CNAs in {label}

| Rank | CNA | CVEs Assigned |
|------|-----|---------------|
"""

    for i, (cna, count) in enumerate(top_cnas, 1):
        blog += f"| {i} | {cna_display(cna)} | {count:,} |\n"

    if "unique_cnas" in stats:
        blog += f"\nIn total, **{stats['unique_cnas']} unique CNAs** assigned CVEs in {label}.\n"

    blog += f"""
---

## Top Vendors

The vendors with the most CVEs attributed to their products this year (each links to its NVD search):

{img("14_top_vendors.png")}

### Top 5 Vendors in {label}

| Rank | Vendor | CVE Count |
|------|--------|-----------|
"""

    for i, (vendor, count) in enumerate(top_vendors, 1):
        blog += f"| {i} | {vendor_link(vendor)} | {count:,} |\n"

    # Products (now after vendors, so "drilling past vendors" is accurate)
    if top_products and len(top_products) > 0:
        blog += f"""
---

## Most Vulnerable Products

Drilling past vendors to specific products, the {label} leaders:

{img("18_top_products.png")}

### Top 5 Products

| Rank | Product | CVE Count |
|------|---------|----------|
"""
        for i, (product, count) in enumerate(top_products[:5], 1):
            blog += f"| {i} | {pretty(product)} | {count:,} |\n"
        blog += (
            "\nProduct-level counts can differ slightly from the vendor totals above: "
            "a vendor's CVEs may span several products, and a single CVE can name more "
            "than one.\n"
        )

    # Known-Exploited Vulnerabilities (CISA KEV)
    if kev_in is not None:
        total_pub = max(kev.get("h1_published_total", 0), 1)
        pct = kev_in / total_pub * 100
        added = kev.get("added_h1", 0)
        added_prior = kev.get("added_h1_prior", 0)
        added_dir = (
            "more than"
            if added > added_prior
            else ("fewer than" if added < added_prior else "the same as")
        )
        blog += f"""
---

## Known-Exploited Vulnerabilities (CISA KEV)

Volume is the headline, but exploitation is what should actually drive patching. Of the **{kev.get("h1_published_total", 0):,}** CVEs published in {label}, only **{kev_in}** ({pct:.2f}%) have shown up in the [CISA KEV catalog]({kev.get("url")}) so far. Treat that as a floor, not a verdict: KEV is a US-government catalog that lags disclosure by months and records only confirmed, observed exploitation, so this share will climb as the {label} cohort ages. Even so, the signal holds, most CVEs are not known-exploited, so exploitability (KEV plus a forward-looking score like EPSS) beats chasing raw counts.

Note these are two different populations: the **{kev_in}** above are {label}-*published* CVEs already in KEV, while CISA *added* **{added}** entries to KEV during the year ({added_dir} the **{added_prior}** added in {PRIOR_YEAR}{same_window}, many of them older CVEs newly exploited), and **{kev.get("ransomware_h1", 0)}** of those additions are tied to known ransomware campaigns.
"""
        ex_rows = ""
        for e in kev.get("examples", [])[:5]:
            cve_link = f"[{e['cve']}](https://www.cve.org/CVERecord?id={e['cve']})"
            ex_rows += (
                f"| {cve_link} | {pretty(e.get('vendor') or '')} | {e.get('product') or ''} | "
                f"{e.get('date_added') or ''} | {'Yes' if e.get('ransomware') else 'No'} |\n"
            )
        if ex_rows:
            _shown = min(5, kev_in)
            blog += f"""
### {label} CVEs Already in KEV

A sample ({_shown} most recent of {kev_in}):

| CVE | Vendor | Product | Added | Ransomware |
|-----|--------|---------|-------|------------|
{ex_rows}"""

    blog += f"""
---

## Data Quality

Not all CVEs have complete metadata. Here's how data quality has evolved over the years:

{img("09_data_quality.png")}

### {label} Data Quality Metrics

| Metric | Coverage |
|--------|----------|
| CVSS Score | {stats["cvss_coverage"]:.1f}% |
| CWE Classification | {stats["cwe_coverage"]:.1f}% |
| CPE Identifiers | {cpe:.1f}% |

This is where two ideas from the *CVE Decaf* work I did with Jay Jacobs get practical: **actionable data quality** (judge a record by whether it is complete enough to act on, not by abstract completeness) and **data provenance** (knowing which source asserted each field). The CPE gap is the clearest case. At **{cpe:.1f}% CPE coverage**, {100 - cpe:.0f}% of {label} CVEs cannot be automatically matched to a product the day they publish, so for those records the answer to "can I act on this today?" is no, no matter how complete the rest of the entry looks. Scoring each record on its provenance (who supplied it) and on the fields that actually drive action (CPE for asset matching, KEV and EPSS for exploitability) is how you turn the raw feed into a measurable signal-to-noise ratio instead of a flat backlog.

---

## Rejected CVEs

Not all CVE IDs stay active. Some are rejected for duplicates, disputes, or invalid submissions, and the rejection rate is a useful read on the ecosystem's quality control.

"""

    if rejected_stats:
        blog += f"""{img("10_rejected_cves.png")}

### {label} Rejection Statistics

| Metric | Value |
|--------|-------|
| Rejected CVEs in {label} | {rejected_stats["rejected_2025"]:,} |
| {label} Rejection Rate | {rejected_stats["rate_2025"]:.2f}% |
| Total Rejected (All Time) | {rejected_stats["total_rejected"]:,} |

CVE rejections occur for several reasons:
- **Duplicates**: The same vulnerability assigned multiple CVE IDs
- **Disputes**: Vendor disagreement that the issue is a vulnerability
- **Invalid**: Not a security vulnerability or insufficient information
- **Withdrawn**: CVE withdrawn by the assigning CNA

"""
    else:
        blog += """*Rejection data analysis unavailable.*

"""

    # Data-driven takeaways: every claim below is checked against the numbers.
    top4 = [c for c, _ in (top_cwes or [])[:4]]
    cwe_names_top = ", ".join(CWE_NAMES.get(c, c) for c in top4)
    memory = [CWE_NAMES.get(c, c) for c in top4 if c in MEMORY_SAFETY_CWES]
    if not memory:
        memory_line = " Memory-safety weaknesses do not make the top four."
    elif len(memory) == 1:
        memory_line = f" {memory[0]} is the only memory-safety weakness in the top four."
    else:
        memory_line = f" {', '.join(memory)} are the memory-safety weaknesses in the top four."

    if new_cnas:
        verb = "is" if len(new_cnas) == 1 else "are"
        cna_takeaway = (
            f"**The CNA mix shifted**: {', '.join(new_cnas)} {verb} new to the top five "
            f"since {PRIOR_YEAR}, and platform teams and research CNAs, not the original "
            "vendors, lead the assigner list."
        )
    elif movers:
        cna_takeaway = (
            f"**The CNA mix held**: the same five CNAs lead as in {PRIOR_YEAR}, with "
            "platform teams and research CNAs, not the original vendors, at the top."
        )
    else:
        cna_takeaway = (
            "**Platforms lead the CNA list**: platform teams and research CNAs, not the "
            "original vendors, assign the most CVEs."
        )

    if complete:
        volume_takeaway = (
            f"**{'A record year' if is_record else 'Volume'}**: {total:,} CVEs, "
            f"{up_down} {abs(yoy):.1f}% on {PRIOR_YEAR}."
        )
    else:
        volume_takeaway = (
            f"**Volume**: {total:,} CVEs through {asof_label}, {up_down} {abs(yoy):.1f}% on "
            f"the same window last year, with the full year projecting to {proj_lo:,}-{proj_hi:,}."
        )

    kev_takeaway = ""
    if kev_in is not None:
        total_pub = max(kev.get("h1_published_total", 0), 1)
        kev_pct_pub = kev_in / total_pub * 100
        kev_takeaway = (
            f"\n\n6. **Confirmed exploitation stays rare (so far)**: just {kev_in} of "
            f"{kev.get('h1_published_total', 0):,} {label} CVEs ({kev_pct_pub:.2f}%) are in CISA "
            "KEV today, a floor that rises as the cohort ages. Volume is a triage problem, not "
            "a patch-everything problem."
        )

    # Role-based "what this means".
    if kev_in is not None:
        defender_line = (
            f"- **If you defend a network:** do not let the raw count set your pace. Only **{kev_pct:.2f}%** of "
            f"{label} CVEs are confirmed-exploited in KEV today, but KEV lags and is a floor, not the full risk "
            f"picture. Lead with exploitability (KEV as a hard floor, EPSS with a threshold you pick), then "
            f"weight by your own context: internet-facing and sensitive systems jump the queue regardless of "
            f"score, and compliance SLAs (PCI, FedRAMP, and the like) still set hard clocks. Lower priority is "
            f"not never, so park the rest in a managed cycle rather than ignoring it."
        )
    else:
        defender_line = (
            "- **If you defend a network:** lead triage with exploitability (KEV as a floor, EPSS with a "
            "threshold), then weight by asset exposure and compliance SLAs. Lower priority is not never."
        )
    role_section = (
        "### What this means for you\n\n"
        + defender_line
        + "\n- **If you run a CNA:** the leaderboard now runs through platforms, ecosystems, and research "
        "CNAs. Volume reflects scope, not padding; the differentiator that is still genuinely uneven is data "
        "quality, and the biggest gap, CPE coverage, is largely an NVD-side enrichment problem rather than a "
        "function of who assigned the CVE.\n"
        + f"- **If you consume NVD data:** enrichment is the bottleneck. CPE at {cpe:.1f}% "
        f"means {100 - cpe:.0f}% of new CVEs lack a formal CPE, which complicates NVD-style automated "
        "matching (many CNAs still carry vendor/product strings), and volume only widens that gap.\n"
    )

    if complete:
        watching_title = f"What I'm watching in {TARGET_YEAR + 1}"
        watching = (
            f"{TARGET_YEAR + 1} starts from a base of **{stats['cves_per_day']:.0f} CVEs a day**, "
            "and the mid-year check-in in July will show whether that pace holds."
        )
    else:
        watching_title = "What I'm watching before December 31"
        watching = (
            f"Whether the pace holds: the projections above put the year at {proj_lo:,} to "
            f"{proj_hi:,}, and the January review settles my mid-year call."
        )

    blog += f"""---

## Conclusions

### Key Takeaways from {label}

1. {volume_takeaway}

2. **Severity stays heavy**: {stats["critical"] + stats["high"]:,} CVEs ({crit_high_pct:.1f}%) are Critical or High.

3. **The top weaknesses**: {cwe_names_top} lead the CWE list.{memory_line}

4. {cna_takeaway}

5. **Coverage gaps persist**: CVSS and CWE are well covered, but CPE sits at {cpe:.1f}%, which still hampers automated matching.{kev_takeaway}

{role_section}
### {watching_title}

{watching}

---

## Methodology and Reproducibility

Two primary data sources, plus two enrichment feeds:

1. **NVD JSON** - National Vulnerability Database export from [nvd.handsonhacking.org](https://nvd.handsonhacking.org/nvd.json)
2. **CVE List V5** - Official CVE records from [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)
3. **Forecast** - my [mid-year call]({call["url"]}) and [CVEForecast](https://cveforecast.org)
4. **Exploitation** - [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

Everything here is reproducible. The full pipeline (Python, pandas, matplotlib) is on GitHub at [{REPO}](https://github.com/{REPO}), and it leans on the free CVE tooling I build at [RogoLabs](https://rogolabs.net): [cve.icu](https://cve.icu), [cnascorecard.org](https://cnascorecard.org), and [cveforecast.org](https://cveforecast.org).

*Data collected and analyzed on {current_date}.*

{citation_block()}

{SERIES_LINE}
"""

    return blog


# Two trailing spaces are a Markdown line break. Built in code so an editor that
# strips trailing whitespace cannot remove it.
HARD_BREAK = "  "


def citation_block():
    """The 'Cite this analysis' quote at the foot of every review.

    Same wording as the block added by hand to the 2022 to 2025 reviews in
    November 2026. The URL comes from period_config, so it is only right if the
    post is published on PUBLISH_DATE with POST_SLUG.
    """
    site = urlparse(SITE_URL).netloc
    return (
        f"> **Cite this analysis**{HARD_BREAK}\n"
        f"> Gamblin, J. ({PUBLISH_DATE[:4]}). *{POST_TITLE}*. {site}. {POST_URL}"
    )


# =============================================================================
# MAIN
# =============================================================================
def main():
    print("=" * 60)
    print(f"{PERIOD_TITLE} CVE Data Review - Blog Generator")
    print("=" * 60)

    # Optional forecast scorecard input (written by 08_forecast_scorecard.py)
    forecast = None
    forecast_path = OUTPUT_DIR / "forecast.json"
    if forecast_path.exists():
        with open(forecast_path) as f:
            forecast = json.load(f)
        print(f"  ✓ Loaded forecast: {forecast.get('full_year_forecast')}")

    # Optional KEV input (written by 09_kev_analysis.py)
    kev = None
    kev_path = OUTPUT_DIR / "kev.json"
    if kev_path.exists():
        with open(kev_path) as f:
            kev = json.load(f)
        print(f"  ✓ Loaded KEV: {kev.get('h1_published_in_kev')} {PERIOD_LABEL} CVEs already exploited")

    # Load data (returns both filtered and full datasets)
    nvd_df, cvelist_df, full_nvd_df, full_cvelist_df = load_data()

    if nvd_df is None and cvelist_df is None:
        print("\nERROR: No data found. Run these scripts first:")
        print("  1. python 01_download_data.py")
        print("  2. python 02_process_data.py")
        return

    # NORMALIZE DATA - Clean and deduplicate before analysis
    nvd_df = normalize_data(nvd_df)
    cvelist_df = normalize_data(cvelist_df)

    # Use NVD as primary, CVE List V5 as secondary
    df = nvd_df if nvd_df is not None else cvelist_df
    full_df = full_nvd_df if full_nvd_df is not None else full_cvelist_df

    if df is None:
        print("\nERROR: No valid data loaded.")
        return

    print(f"\nUsing primary dataset: {len(df):,} active CVEs (excluded rejected)")

    # Calculate statistics
    print("\nCalculating statistics...")
    stats = calculate_stats(df, cvelist_df, full_nvd_df, full_cvelist_df)

    # Sanity check: warn when a top product/vendor is dominated by one outside CNA
    # (the OpenClaw/VulnCheck pattern) so an inflated callout never ships silently.
    concentration = cna_concentration(cvelist_df, stats["asof"])
    if concentration:
        with open(OUTPUT_DIR / "cna_concentration.json", "w") as f:
            json.dump(concentration, f, indent=2)

    # Generate all graphs using imported functions from 03_generate_graphs.py
    print("\nGenerating graphs...")

    # CVEs by Year over the same elapsed window - returns (fig, yearly) for the
    # YoY chart. Once the year closes this is simply CVEs per calendar year.
    asof = current_asof(df)
    _, window_yearly = graph_cves_by_year(
        df, asof, save_path=GRAPHS_DIR / "01_cves_by_year.png"
    )

    # YoY Growth (derived from the same-window series)
    graph_yoy_growth(window_yearly, save_path=GRAPHS_DIR / "02_yoy_growth.png")

    # Cumulative Growth uses the TRUE full-year totals (all-time catalog size)
    yearly_full = df.groupby("year").size().reset_index(name="count")
    yearly_full = yearly_full[
        (yearly_full["year"] >= HIST_MIN_YEAR) & (yearly_full["year"] <= TARGET_YEAR)
    ]
    _, cumulative_total = graph_cumulative_growth(
        yearly_full, save_path=GRAPHS_DIR / "03_cumulative_growth.png"
    )

    # Monthly - returns (fig, peak_month, peak_count)
    _, peak_month, peak_count = graph_period_monthly(
        df, save_path=GRAPHS_DIR / "04_monthly.png"
    )

    # CVSS Distribution
    graph_cvss_distribution(df, save_path=GRAPHS_DIR / "05_cvss_distribution.png")

    # Severity Breakdown
    graph_severity_breakdown(df, save_path=GRAPHS_DIR / "06_severity_breakdown.png")

    # Top CWEs - returns (fig, top_cwes_list)
    _, top_cwes = graph_top_cwes(df, save_path=GRAPHS_DIR / "07_top_cwes.png")
    if top_cwes is None:
        top_cwes = []

    # Data Quality
    graph_data_quality(df, save_path=GRAPHS_DIR / "09_data_quality.png")

    # CVSS by Year
    graph_cvss_by_year(df, save_path=GRAPHS_DIR / "13_cvss_by_year.png")

    # Rejected CVE analysis (uses full dataset) - returns (fig, rejected_stats)
    rejected_stats = None
    if full_df is not None:
        result = graph_rejected_cves(
            full_df, save_path=GRAPHS_DIR / "10_rejected_cves.png"
        )
        if result is not None:
            _, rejected_stats = result

    # CVE List V5 specific graphs
    cna_df = cvelist_df if cvelist_df is not None else df

    # Top CNAs - returns (fig, top_cnas_list)
    _, top_cnas = graph_top_cnas(cna_df, save_path=GRAPHS_DIR / "08_top_cnas.png")
    if top_cnas is None:
        top_cnas = []

    # Top Vendors - returns (fig, top_vendors_list)
    _, top_vendors = graph_top_vendors(
        cna_df, save_path=GRAPHS_DIR / "14_top_vendors.png"
    )
    if top_vendors is None:
        top_vendors = []

    # Day of Week Analysis - returns (fig, day_stats_dict)
    _, day_stats = graph_day_of_week(df, save_path=GRAPHS_DIR / "16_day_of_week.png")

    # Top Days Analysis - returns (fig, top_days_list)
    _, top_days = graph_top_days(df, save_path=GRAPHS_DIR / "17_top_days.png")
    if top_days is None:
        top_days = []

    # Top Products Analysis - returns (fig, top_products_list)
    _, top_products = graph_top_products(
        df, save_path=GRAPHS_DIR / "18_top_products.png"
    )
    if top_products is None:
        top_products = []

    # Social scorecard (shareable launch image)
    proj_lo = min(stats["projected_runrate"], stats["projected_seasonal"])
    proj_hi = max(stats["projected_runrate"], stats["projected_seasonal"])
    kev_txt = (
        f"{kev['h1_published_in_kev']}"
        if kev and kev.get("h1_published_in_kev") is not None
        else "n/a"
    )
    complete = stats["window_complete"]
    fifth_tile = (
        (f"{stats['avg_cvss']:.2f}", "average CVSS", False)
        if complete
        else (f"{round(proj_lo / 1000)}-{round(proj_hi / 1000)}K", "projected full year", False)
    )
    scorecard_tiles = [
        (f"{stats['total_2025']:,}", f"CVEs in {PERIOD_LABEL}", True),
        (f"{stats['cves_per_day']:.0f}/day", f"1 every {stats['minutes_between']:.0f} min", False),
        (
            f"{stats['yoy_change']:+.0f}%",
            f"vs {PRIOR_YEAR}" + ("" if complete else " (same window)"),
            False,
        ),
        (kev_txt, "known-exploited (CISA KEV)", True),
        fifth_tile,
        (str(stats.get("top_cna", "n/a")).split("_")[0], "top CVE issuer", False),
    ]
    graph_scorecard(
        scorecard_tiles,
        f"{PERIOD_LABEL} CVE Data: Year in Review" if complete else f"{PERIOD_LABEL} CVE Data: Preview",
        subtitle=f"January 1 - {stats['asof_label']}, {TARGET_YEAR}",
        save_path=GRAPHS_DIR / "00_scorecard.png",
    )

    # Alt text for every chart, written beside the graphs so the publish step
    # can set it on each upload even if 05_enrich_blog.py rewrites the Markdown.
    alt_text = chart_alt_text(
        stats,
        top_cwes,
        top_cnas,
        top_vendors,
        peak_month,
        peak_count,
        rejected_stats,
        day_stats,
        top_days,
        top_products,
    )
    with open(GRAPHS_DIR / "alt_text.json", "w") as f:
        json.dump(alt_text, f, indent=2, sort_keys=True)
        f.write("\n")

    # Generate blog
    print("\nGenerating blog.md...")
    blog_content = generate_blog(
        stats,
        top_cwes,
        top_cnas,
        top_vendors,
        peak_month,
        peak_count,
        cumulative_total,
        rejected_stats,
        day_stats,
        top_days,
        top_products,
        forecast,
        kev,
        alt_text=alt_text,
    )

    with open("blog.md", "w") as f:
        f.write(blog_content)

    print("\n" + "=" * 60)
    print("COMPLETE!")
    print("=" * 60)
    print("\n✓ Blog saved to: blog.md")
    print(f"✓ Graphs saved to: {GRAPHS_DIR}/")
    print(f"✓ Alt text saved to: {GRAPHS_DIR / 'alt_text.json'}")
    print(f"\nGenerated {len(list(GRAPHS_DIR.glob('*.png')))} graphs")
    print("\nNext: python3 10_publish_wordpress.py to check it, then --upload for a draft.")


if __name__ == "__main__":
    main()
