#!/usr/bin/env python3
"""
Convert the generated Markdown post into WordPress block markup.

Covers the subset of Markdown that 04_generate_blog.py (and 05_enrich_blog.py)
produce: headings, paragraphs, pipe tables, images on their own line, bullet and
numbered lists, block quotes, horizontal rules and HTML comments, plus inline
bold, italic, code and links.

The markup matches what the block editor itself saves, checked against the
save functions in WordPress 7.0.3 (wp-includes/js/dist/block-library.js), so the
draft opens in the editor without "unexpected content" warnings:

- core/paragraph saves a bare <p>: its block.json sets supports.className false.
- core/heading and core/list add their wp-block-* class.
- core/table puts has-fixed-layout on the <table> (hasFixedLayout defaults to
  true), keeps a scope attribute on <th>, and saves its caption as
  <figcaption class="wp-element-caption">.
- core/image puts size-<slug> on the <figure> and wp-image-<id> on the <img>.
  That class is how WordPress finds the attachment and adds srcset when the
  post renders, which is the reason charts go through the media library.
- core/separator saves <hr class="wp-block-separator has-alpha-channel-opacity"/>.

Two things are deliberate rather than literal translations:

- Header cells get scope="col", so screen readers can announce the column for
  each cell. The tables were published without it.
- A paragraph of the form "Table: some caption" straight after a table becomes
  that table's caption, which is how Pandoc writes table captions.
"""

import html
import json
import re

IMAGE_LINE = re.compile(r"^!\[([^\]]*)\]\(([^)\s]+)\)\s*$")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
RULE = re.compile(r"^\s*(?:-{3,}|\*{3,}|_{3,})\s*$")
LIST_ITEM = re.compile(r"^\s*([-*+]|\d+[.)])\s+(.*)$")
CAPTION = re.compile(r"^Table:\s*(.+)$")


# -----------------------------------------------------------------------------
# Inline Markdown
# -----------------------------------------------------------------------------
def inline(text):
    """Bold, italic, code and links to HTML, with everything else escaped.

    Underscore emphasis is not supported on purpose: CNA short names such as
    GitHub_M would otherwise turn into italics.
    """
    codes = []

    def keep_code(m):
        codes.append(f"<code>{html.escape(m.group(1), quote=False)}</code>")
        return f"\x00{len(codes) - 1}\x00"

    text = re.sub(r"`([^`]+)`", keep_code, text)
    text = html.escape(text, quote=False)
    text = re.sub(
        r"\[([^\]]+)\]\(([^)\s]+)\)",
        lambda m: f'<a href="{m.group(2).replace(chr(34), "&quot;")}">{m.group(1)}</a>',
        text,
    )
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<![*\w])\*(?![\s*])(.+?)(?<![\s*])\*(?![*\w])", r"<em>\1</em>", text)
    return re.sub(r"\x00(\d+)\x00", lambda m: codes[int(m.group(1))], text)


def inline_lines(lines):
    """Join paragraph lines. A trailing double space or backslash is a <br>."""
    out = ""
    for i, line in enumerate(lines):
        last = i == len(lines) - 1
        hard = line.endswith("  ") or line.endswith("\\")
        body = inline(line.rstrip(" \\").strip() if hard else line.strip())
        out += body if last else body + ("<br>" if hard else " ")
    return out.strip()


# -----------------------------------------------------------------------------
# Block parsing
# -----------------------------------------------------------------------------
def _split_row(line):
    cells = line.strip().replace("\\|", "\x01").strip("|").split("|")
    return [c.strip().replace("\x01", "|") for c in cells]


def _is_block_start(line):
    s = line.lstrip()
    return bool(
        HEADING.match(line)
        or RULE.match(line)
        or s.startswith("|")
        or s.startswith(">")
        or s.startswith("<!--")
        or LIST_ITEM.match(line)
        or IMAGE_LINE.match(line.strip())
    )


def parse(markdown):
    """Return (title, nodes). The first level-one heading is the post title."""
    lines = markdown.splitlines()
    title = None
    nodes = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        if stripped.startswith("<!--"):
            while i < n and "-->" not in lines[i]:
                i += 1
            i += 1
            continue

        m = HEADING.match(line)
        if m:
            level = len(m.group(1))
            if level == 1 and title is None:
                title = m.group(2)
            else:
                nodes.append(("heading", level, m.group(2)))
            i += 1
            continue

        if RULE.match(line):
            nodes.append(("separator",))
            i += 1
            continue

        if stripped.startswith("|"):
            rows = []
            while i < n and lines[i].strip().startswith("|"):
                rows.append(_split_row(lines[i]))
                i += 1
            header, body = rows[0], rows[1:]
            if body and all(re.fullmatch(r":?-{1,}:?", c or "-") for c in body[0]):
                body = body[1:]
            # A "Table: ..." paragraph right after the table is its caption.
            j = i
            while j < n and not lines[j].strip():
                j += 1
            caption = None
            if j < n:
                cm = CAPTION.match(lines[j].strip())
                if cm:
                    caption = cm.group(1)
                    i = j + 1
            nodes.append(("table", header, body, caption))
            continue

        if stripped.startswith(">"):
            quoted = []
            while i < n and lines[i].lstrip().startswith(">"):
                quoted.append(re.sub(r"^\s*>\s?", "", lines[i]))
                i += 1
            nodes.append(("quote", parse("\n".join(quoted))[1]))
            continue

        m = LIST_ITEM.match(line)
        if m:
            ordered = m.group(1)[0].isdigit()
            start = int(re.sub(r"\D", "", m.group(1))) if ordered else None
            items = []
            while i < n:
                cur = lines[i]
                im = LIST_ITEM.match(cur)
                if im and im.group(1)[0].isdigit() == ordered:
                    items.append([im.group(2)])
                    i += 1
                elif cur.strip() and not _is_block_start(cur) and items:
                    items[-1].append(cur.strip())  # wrapped continuation line
                    i += 1
                elif not cur.strip():
                    # A loose list: blank lines between items of the same kind.
                    j = i
                    while j < n and not lines[j].strip():
                        j += 1
                    nm = LIST_ITEM.match(lines[j]) if j < n else None
                    if nm and nm.group(1)[0].isdigit() == ordered:
                        i = j
                    else:
                        break
                else:
                    break
            nodes.append(("list", ordered, start, items))
            continue

        m = IMAGE_LINE.match(stripped)
        if m:
            nodes.append(("image", m.group(2), m.group(1)))
            i += 1
            continue

        para = []
        while i < n and lines[i].strip() and (not para or not _is_block_start(lines[i])):
            para.append(lines[i])
            i += 1
        nodes.append(("paragraph", para))

    return title, nodes


def images(nodes):
    """Every image path referenced, in order, including inside quotes."""
    found = []
    for node in nodes:
        if node[0] == "image":
            found.append(node[1])
        elif node[0] == "quote":
            found.extend(images(node[1]))
    return found


# -----------------------------------------------------------------------------
# Block rendering
# -----------------------------------------------------------------------------
def _attrs(attrs):
    """Block comment attributes, serialized the way WordPress does."""
    if not attrs:
        return ""
    raw = json.dumps(attrs, separators=(",", ":"), ensure_ascii=False)
    for a, b in (("--", "\\u002d\\u002d"), ("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026")):
        raw = raw.replace(a, b)
    return " " + raw


def block(name, inner, attrs=None):
    return f"<!-- wp:{name}{_attrs(attrs)} -->\n{inner}\n<!-- /wp:{name} -->"


def render_image(src, alt, media=None):
    """Image block. With an uploaded attachment it carries id and wp-image-<id>."""
    alt_attr = html.escape(alt, quote=True)
    if media:
        size = media.get("size", "large")
        attrs = {"id": media["id"], "sizeSlug": size, "linkDestination": "none"}
        img = f'<img src="{media["url"]}" alt="{alt_attr}" class="wp-image-{media["id"]}"/>'
    else:
        size = "large"
        attrs = {"sizeSlug": size, "linkDestination": "none"}
        img = f'<img src="{html.escape(src, quote=True)}" alt="{alt_attr}"/>'
    return block("image", f'<figure class="wp-block-image size-{size}">{img}</figure>', attrs)


def render_table(header, body, caption=None):
    width = len(header)
    head = "".join(f'<th scope="col">{inline(c)}</th>' for c in header)
    rows = ""
    for row in body:
        row = (row + [""] * width)[:width]
        rows += "<tr>" + "".join(f"<td>{inline(c)}</td>" for c in row) + "</tr>"
    cap = f'<figcaption class="wp-element-caption">{inline(caption)}</figcaption>' if caption else ""
    inner = (
        '<figure class="wp-block-table is-style-stripes"><table class="has-fixed-layout">'
        f"<thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>{cap}</figure>"
    )
    # The published reviews use the Stripes table style.
    return block("table", inner, {"className": "is-style-stripes"})


def render(nodes, media=None, alt_text=None):
    """Block markup for the post body.

    ``media`` maps an image path to {"id", "url", "size"} once it is uploaded.
    ``alt_text`` maps a chart's file name to its alt text, and wins over the
    alt text written in the Markdown.
    """
    media = media or {}
    alt_text = alt_text or {}
    out = []
    for node in nodes:
        kind = node[0]
        if kind == "heading":
            _, level, text = node
            attrs = None if level == 2 else {"level": level}
            out.append(block("heading", f'<h{level} class="wp-block-heading">{inline(text)}</h{level}>', attrs))
        elif kind == "paragraph":
            out.append(block("paragraph", f"<p>{inline_lines(node[1])}</p>"))
        elif kind == "separator":
            out.append(block("separator", '<hr class="wp-block-separator has-alpha-channel-opacity"/>'))
        elif kind == "table":
            out.append(render_table(*node[1:]))
        elif kind == "image":
            _, src, md_alt = node
            name = src.rsplit("/", 1)[-1]
            out.append(render_image(src, alt_text.get(name, md_alt), media.get(src)))
        elif kind == "list":
            _, ordered, start, items = node
            tag = "ol" if ordered else "ul"
            attrs = {}
            start_attr = ""
            if ordered:
                attrs["ordered"] = True
                if start and start != 1:
                    attrs["start"] = start
                    start_attr = f' start="{start}"'
            lis = "".join(
                block("list-item", f"<li>{inline_lines(item)}</li>") for item in items
            )
            out.append(block("list", f'<{tag} class="wp-block-list"{start_attr}>{lis}</{tag}>', attrs))
        elif kind == "quote":
            inner = render(node[1], media, alt_text)
            out.append(block("quote", f'<blockquote class="wp-block-quote">{inner}</blockquote>'))
    return "\n\n".join(out)


def convert(markdown, media=None, alt_text=None):
    """Markdown in, (title, block markup) out."""
    title, nodes = parse(markdown)
    return title, render(nodes, media, alt_text)
