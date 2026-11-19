"""Tests for the chart alt text and the citation block in 04_generate_blog.py."""

import importlib.util
import os
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


def load_generator():
    # 04 loads 03 by a relative path, so import it from the project root.
    cwd = os.getcwd()
    os.chdir(ROOT)
    try:
        spec = importlib.util.spec_from_file_location("generate_blog", ROOT / "04_generate_blog.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        os.chdir(cwd)


STATS = {
    "total_2025": 34601,
    "yoy_change": -2.5,
    "total_all_time": 343497,
    "avg_cvss": 6.881,
    "median_cvss": 7.1,
    "cvss_coverage": 93.4,
    "cwe_coverage": 95.3,
    "cpe_coverage": 58.5,
    "critical": 3446,
    "high": 13378,
    "medium": 14162,
    "low": 2974,
}


def alt_text(**overrides):
    gen = load_generator()
    args = dict(
        stats=STATS,
        top_cwes=[("CWE-79", 3710), ("CWE-862", 1639), ("CWE-89", 1404), ("CWE-22", 900)],
        top_cnas=[("GitHub_M", 6730), ("VulDB", 3218)],
        top_vendors=[("linux", 2516)],
        peak_month="Jun",
        peak_count=7454,
        rejected_stats={"rejected_2025": 1258, "rate_2025": 3.512, "total_rejected": 9000},
        day_stats={"peak_day": "Wed", "peak_count": 7943, "tuesday_count": 7081},
        top_days=[("2026-06-09", 747), ("2026-06-17", 732)],
        top_products=[("linux_kernel", 1915)],
    )
    args.update(overrides)
    return gen.chart_alt_text(**args)


def test_every_chart_in_the_post_has_alt_text():
    alt = alt_text()
    for name in [
        "01_cves_by_year.png", "02_yoy_growth.png", "03_cumulative_growth.png",
        "04_h1_monthly.png", "05_cvss_distribution.png", "06_severity_breakdown.png",
        "07_top_cwes.png", "08_top_cnas.png", "09_data_quality.png",
        "10_rejected_cves.png", "13_cvss_by_year.png", "14_top_vendors.png",
        "16_day_of_week.png", "17_top_days.png", "18_top_products.png",
    ]:
        assert name in alt, name
        assert any(ch.isdigit() for ch in alt[name]), f"{name} has no number: {alt[name]}"


def test_alt_text_states_the_numbers():
    alt = alt_text()
    assert alt["02_yoy_growth.png"].endswith("down 2.5% on the first half of 2025")
    assert "peaking in June at 7,454" in alt["04_h1_monthly.png"]
    assert "Unscored 641" in alt["06_severity_breakdown.png"]
    assert "CWE-79 (XSS) 3,710" in alt["07_top_cwes.png"]
    assert "CWE-22" not in alt["07_top_cwes.png"]  # top three only
    assert "Wednesday leads with 7,943 and Tuesday has 7,081" in alt["16_day_of_week.png"]
    assert "led by June 9 with 747 CVEs and June 17 with 732" in alt["17_top_days.png"]
    assert "3.51% rejection rate" in alt["10_rejected_cves.png"]
    assert "GitHub Security Advisories 6,730, VulDB 3,218" in alt["08_top_cnas.png"]
    assert "GitHub_M" not in alt["08_top_cnas.png"]


def test_tuesday_peak_is_not_repeated():
    alt = alt_text(day_stats={"peak_day": "Tue", "peak_count": 8000, "tuesday_count": 8000})
    assert alt["16_day_of_week.png"].endswith("Tuesday leads with 8,000")


def test_alt_text_cannot_break_markdown():
    alt = alt_text(top_cnas=[("odd[name]", 5)])
    assert "[" not in alt["08_top_cnas.png"] and "]" not in alt["08_top_cnas.png"]


def test_citation_block_uses_the_configured_post():
    from period_config import POST_TITLE, POST_URL

    block = load_generator().citation_block()
    assert block.startswith("> **Cite this analysis**  \n> Gamblin, J. (")
    assert f"*{POST_TITLE}*" in block and block.endswith(POST_URL)
