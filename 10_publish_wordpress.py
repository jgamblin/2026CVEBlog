#!/usr/bin/env python3
"""
Turn blog.md into a WordPress draft on jerrygamblin.com, charts and all.

By default this is a dry run. It converts the post to block markup, writes it to
blog_wordpress.html, and checks the things that went wrong on earlier reviews:
charts too large for the page, alt text that only repeats a heading, and a
missing citation or series link. Nothing leaves this machine.

With --upload it does what used to be done by hand in wp-admin:

1. Uploads every chart the post uses to the media library, with its alt text
   from graphs/alt_text.json. Going through the media library is what gives
   each chart a srcset; the 2025 review loaded them straight from GitHub and
   every reader downloaded the full-size files.
2. Creates the post as a draft (never published), with its slug, date and tags
   from period_config.py, and prints the link to review it in the editor.

Run it again after regenerating and it updates the same draft and reuses charts
that have not changed. It refuses to touch a post that is no longer a draft.

Credentials come from the environment and are never written anywhere:

    WP_USER          your WordPress username
    WP_APP_PASSWORD  an application password from Users > Profile in wp-admin

Usage:
    python3 10_publish_wordpress.py                      # dry run on blog.md
    python3 10_publish_wordpress.py --input blog_enriched.md
    python3 10_publish_wordpress.py --upload             # create or update the draft
"""

import argparse
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

from period_config import (
    POST_SLUG,
    POST_TAGS,
    POST_TITLE,
    POST_URL,
    PUBLISH_DATE,
    SERIES_LINE,
    SITE_URL,
)
from wp_blocks import convert, images, parse

ALT_TEXT_FILE = Path("graphs/alt_text.json")
MEDIA_CACHE = Path("processed/wp_media.json")
POST_CACHE = Path("processed/wp_post.json")
PREVIEW_FILE = Path("blog_wordpress.html")
SCORECARD = "graphs/00_scorecard.png"

# Twice the 660px text column. Anything much wider is the 300 dpi problem again.
MAX_CHART_WIDTH = 2000


def png_size(path):
    """(width, height) of a PNG from its header, without needing Pillow."""
    with open(path, "rb") as f:
        head = f.read(24)
    if head[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    return struct.unpack(">II", head[16:24])


def load_json(path, default):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return default


def save_json(path, data):
    Path(path).parent.mkdir(exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def check(markdown, nodes, alt_text):
    """Problems worth stopping for before anything is uploaded."""
    problems = []
    for src in images(nodes):
        name = src.rsplit("/", 1)[-1]
        path = Path(src)
        if not path.exists():
            problems.append(f"{src}: file not found")
            continue
        size = png_size(path)
        if size and size[0] > MAX_CHART_WIDTH:
            problems.append(
                f"{src}: {size[0]}px wide, over {MAX_CHART_WIDTH}px. Check SAVE_DPI in style_config.py"
            )
        if name not in alt_text:
            problems.append(f"{src}: no alt text in {ALT_TEXT_FILE}, rerun 04_generate_blog.py")
    if POST_URL not in markdown:
        problems.append(f"the citation URL {POST_URL} is not in the post")
    if SERIES_LINE.split("(")[0] not in markdown:
        problems.append("the series line from period_config.SERIES_LINE is not in the post")
    return problems


# -----------------------------------------------------------------------------
# WordPress REST API
# -----------------------------------------------------------------------------
class WordPress:
    def __init__(self, base, user, password):
        import requests

        self.api = base.rstrip("/") + "/wp-json/wp/v2"
        self.http = requests.Session()
        self.http.auth = (user, password)
        self.http.headers["User-Agent"] = "cve-review-publisher"

    def _ok(self, r, what):
        if r.status_code >= 400:
            sys.exit(f"{what} failed: HTTP {r.status_code} {r.text[:300]}")
        return r.json()

    def get(self, path, what, **params):
        return self._ok(self.http.get(self.api + path, params=params, timeout=60), what)

    def post(self, path, what, **kw):
        return self._ok(self.http.post(self.api + path, timeout=120, **kw), what)

    def exists(self, path):
        return self.http.get(self.api + path, params={"_fields": "id"}, timeout=60).status_code == 200


def media_entry(item):
    """The large size if WordPress made one, otherwise the original."""
    sizes = (item.get("media_details") or {}).get("sizes") or {}
    if "large" in sizes:
        return {"id": item["id"], "url": sizes["large"]["source_url"], "size": "large"}
    return {"id": item["id"], "url": item["source_url"], "size": "full"}


def upload_charts(wp, srcs, alt_text):
    """Upload each chart once. Unchanged files are reused, with alt text kept in sync."""
    cache = load_json(MEDIA_CACHE, {})
    media = {}
    for src in srcs:
        name = src.rsplit("/", 1)[-1]
        data = Path(src).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        alt = alt_text[name]
        hit = cache.get(name)
        if hit and hit["sha256"] == digest and wp.exists(f"/media/{hit['id']}"):
            item = wp.post(f"/media/{hit['id']}", f"updating alt text on {name}", json={"alt_text": alt})
            print(f"  reused   {name} (media {hit['id']})")
        else:
            item = wp.post(
                "/media",
                f"uploading {name}",
                params={"alt_text": alt},
                data=data,
                headers={
                    "Content-Disposition": f'attachment; filename="{name}"',
                    "Content-Type": "image/png",
                },
            )
            print(f"  uploaded {name} (media {item['id']})")
        media[src] = media_entry(item)
        cache[name] = {"sha256": digest, **media[src]}
        save_json(MEDIA_CACHE, cache)  # after every file, so a failure never re-uploads
    return media


def tag_ids(wp):
    found = wp.get("/tags", "looking up tags", slug=",".join(POST_TAGS), _fields="id,slug")
    by_slug = {t["slug"]: t["id"] for t in found}
    missing = [s for s in POST_TAGS if s not in by_slug]
    if missing:
        sys.exit(f"tags not on the site: {', '.join(missing)}. Create them in wp-admin first.")
    return [by_slug[s] for s in POST_TAGS]


def draft_to_update(wp):
    """The cached draft's id, None for a new draft, or exit if neither is safe.

    Runs before any chart is uploaded, so a refusal leaves nothing behind in the
    media library.
    """
    live = wp.get("/posts", "checking the slug", slug=POST_SLUG, status="publish,future", _fields="id,link")
    if live:
        sys.exit(
            f"{live[0]['link']} is already live with slug '{POST_SLUG}'. "
            "Set POST_SLUG and PUBLISH_DATE in period_config.py for the new post."
        )
    cached = load_json(POST_CACHE, {})
    if not cached.get("id") or not wp.exists(f"/posts/{cached['id']}"):
        return None
    current = wp.get(f"/posts/{cached['id']}", "reading the draft", context="edit", _fields="id,status")
    if current["status"] not in ("draft", "pending"):
        sys.exit(
            f"post {cached['id']} is '{current['status']}', not a draft. Refusing to overwrite it. "
            f"Delete {POST_CACHE} to create a new draft instead."
        )
    return cached["id"]


def save_draft(wp, post_id, title, content, tags):
    fields = {
        "title": title,
        "content": content,
        "status": "draft",
        "slug": POST_SLUG,
        # Fixing the date keeps the permalink, and so the citation, correct when
        # the draft is published later.
        "date": f"{PUBLISH_DATE}T08:00:00",
        "tags": tags,
    }
    if post_id:
        post = wp.post(f"/posts/{post_id}", "updating the draft", json=fields)
        print(f"Updated draft {post['id']}")
    else:
        post = wp.post("/posts", "creating the draft", json=fields)
        save_json(POST_CACHE, {"id": post["id"]})
        print(f"Created draft {post['id']}")
    return post


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", default="blog.md", help="Markdown to publish (default: blog.md)")
    parser.add_argument("--title", help=f"post title (default: the post's H1, or {POST_TITLE!r})")
    parser.add_argument("--upload", action="store_true", help="upload charts and create or update the draft")
    args = parser.parse_args()

    markdown = Path(args.input).read_text()
    alt_text = load_json(ALT_TEXT_FILE, {})
    md_title, nodes = parse(markdown)
    title = args.title or md_title or POST_TITLE
    srcs = images(nodes)

    print(f"Title:  {title}")
    print(f"URL:    {POST_URL} (on publish)")
    print(f"Tags:   {', '.join(POST_TAGS)}")
    print(f"Charts: {len(srcs)}")
    if Path(SCORECARD).exists():
        print(f"Share image: {SCORECARD} is not in the post body. Set it as the featured image if you want it on social cards.")

    problems = check(markdown, nodes, alt_text)
    for p in problems:
        print(f"  ! {p}")
    if problems:
        sys.exit(f"{len(problems)} problem(s). Fix them before uploading.")

    _, preview = convert(markdown, alt_text=alt_text)
    PREVIEW_FILE.write_text(preview + "\n")
    print(f"Block markup written to {PREVIEW_FILE} (local chart paths, no uploads)")

    if not args.upload:
        print("Dry run. Add --upload to create the draft.")
        return

    user, password = os.environ.get("WP_USER"), os.environ.get("WP_APP_PASSWORD")
    if not user or not password:
        sys.exit("Set WP_USER and WP_APP_PASSWORD (an application password, not your login password).")

    wp = WordPress(SITE_URL, user, password)
    wp.get("/users/me", "checking the credentials", context="edit", _fields="id")
    tags = tag_ids(wp)
    post_id = draft_to_update(wp)
    print("Charts:")
    media = upload_charts(wp, srcs, alt_text)
    _, content = convert(markdown, media=media, alt_text=alt_text)
    post = save_draft(wp, post_id, title, content, tags)
    print(f"Review it: {SITE_URL}/wp-admin/post.php?post={post['id']}&action=edit")
    print("It stays a draft until you publish it in the editor.")


if __name__ == "__main__":
    main()
