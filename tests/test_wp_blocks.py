"""Tests for the Markdown to WordPress block conversion."""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from wp_blocks import convert, images, inline, parse  # noqa: E402


def blocks(markup):
    """Names of the top-level blocks, in order."""
    names, depth = [], 0
    for m in re.finditer(r"<!-- (/?)wp:([a-z-]+)", markup):
        if m.group(1):
            depth -= 1
        else:
            if depth == 0:
                names.append(m.group(2))
            depth += 1
    assert depth == 0, "unbalanced block comments"
    return names


def test_title_comes_from_h1_and_is_not_in_the_body():
    title, body = convert("# My Review\n\nHello.\n")
    assert title == "My Review"
    assert "My Review" not in body
    assert blocks(body) == ["paragraph"]


def test_paragraph_saves_without_a_class():
    _, body = convert("Hello **world**.")
    assert "<p>Hello <strong>world</strong>.</p>" in body


def test_heading_levels():
    _, body = convert("## Two\n\n### Three\n")
    assert '<!-- wp:heading -->\n<h2 class="wp-block-heading">Two</h2>' in body
    assert '<!-- wp:heading {"level":3} -->\n<h3 class="wp-block-heading">Three</h3>' in body


def test_table_has_scope_fixed_layout_and_stripes():
    md = "| Rank | CNA |\n|------|-----|\n| 1 | GitHub_M |\n| 2 | VulDB |\n"
    _, body = convert(md)
    assert blocks(body) == ["table"]
    assert '<!-- wp:table {"className":"is-style-stripes"} -->' in body
    assert '<table class="has-fixed-layout">' in body
    assert '<th scope="col">Rank</th><th scope="col">CNA</th>' in body
    assert "<td>GitHub_M</td>" in body  # underscore is not emphasis
    assert "<figcaption" not in body


def test_table_caption_from_pandoc_style_line():
    md = "| A |\n|---|\n| 1 |\n\nTable: Top CNAs, H1 2026\n\nNext.\n"
    _, body = convert(md)
    assert '<figcaption class="wp-element-caption">Top CNAs, H1 2026</figcaption>' in body
    assert blocks(body) == ["table", "paragraph"]


def test_short_rows_are_padded():
    _, body = convert("| A | B |\n|---|---|\n| 1 |\n")
    assert "<tr><td>1</td><td></td></tr>" in body


def test_image_uses_alt_text_file_over_markdown_alt():
    md = "![Top CNAs](graphs/08_top_cnas.png)\n"
    alt = {"08_top_cnas.png": 'Bar chart of CNAs: GitHub_M 6,730 & "others"'}
    _, body = convert(md, alt_text=alt)
    assert 'alt="Bar chart of CNAs: GitHub_M 6,730 &amp; &quot;others&quot;"' in body
    assert "Top CNAs" not in body


def test_uploaded_image_gets_id_and_wp_image_class():
    md = "![x](graphs/01.png)\n"
    media = {"graphs/01.png": {"id": 42, "url": "https://example.test/01-1024x511.png", "size": "large"}}
    _, body = convert(md, media=media)
    assert '<!-- wp:image {"id":42,"sizeSlug":"large","linkDestination":"none"} -->' in body
    assert '<figure class="wp-block-image size-large">' in body
    assert 'class="wp-image-42"' in body


def test_loose_numbered_list_is_one_list():
    md = "1. **One**: a\n\n2. **Two**: b\n\n3. Three\n\n### After\n"
    _, body = convert(md)
    assert blocks(body) == ["list", "heading"]
    assert '<!-- wp:list {"ordered":true} -->\n<ol class="wp-block-list">' in body
    assert body.count("<!-- wp:list-item -->") == 3


def test_bullet_list_then_paragraph():
    md = "- a\n- b\n\nAfter.\n"
    _, body = convert(md)
    assert blocks(body) == ["list", "paragraph"]
    assert '<ul class="wp-block-list">' in body


def test_quote_with_hard_break_matches_citation_block():
    md = "> **Cite this analysis**  \n> Gamblin, J. (2027). *2026 CVE Data Review*. jerrygamblin.com. https://x.test/\n"
    _, body = convert(md)
    assert blocks(body) == ["quote"]
    assert '<blockquote class="wp-block-quote"><!-- wp:paragraph -->' in body
    assert "<strong>Cite this analysis</strong><br>Gamblin, J. (2027). <em>2026 CVE Data Review</em>." in body


def test_separator_and_comment():
    _, body = convert("<!-- note to self -->\n\nA\n\n---\n\nB\n")
    assert blocks(body) == ["paragraph", "separator", "paragraph"]
    assert '<hr class="wp-block-separator has-alpha-channel-opacity"/>' in body
    assert "note to self" not in body


def test_inline_escapes_and_links():
    assert inline("a < b & c") == "a &lt; b &amp; c"
    assert inline("[NVD](https://nvd.test/?a=1&b=2)") == '<a href="https://nvd.test/?a=1&amp;b=2">NVD</a>'
    assert inline("`x < y`") == "<code>x &lt; y</code>"
    assert inline("*(partial)*") == "<em>(partial)</em>"


def test_images_lists_every_chart_in_order():
    md = "![a](graphs/a.png)\n\ntext\n\n> ![b](graphs/b.png)\n"
    assert images(parse(md)[1]) == ["graphs/a.png", "graphs/b.png"]
