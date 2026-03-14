"""
K blog crawler — extension analysis lessons and IOCs.

Crawls a security research blog (K) for posts about malicious browser
extensions, VS Code extensions, and campaigns (DarkSpectre, GhostPoster,
RedDirection, SpyVPN, VK Styles, GreedyBear, etc.). Extracts extension IDs,
domains, and behavior keywords, then:
- Saves data/k/k_posts.json and k_consolidated.json
- Optionally updates docs/K_LESSONS_LEARNT.md

Run from repo root:
  python scripts/k_crawler.py
  python scripts/k_crawler.py --max-posts 20 --write-lessons
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

REPO_ROOT = Path(__file__).resolve().parent.parent
BLOG_INDEX_URL = "https://www.koi.ai/blog/"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Chrome-Extension-Security-Analyzer"
EXTENSION_ID_RE = re.compile(r"\b([a-z]{32})\b")
DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,}|[a-zA-Z]+\.[a-zA-Z]+))\b")
BEHAVIOR_KEYWORDS = re.compile(
    r"\b(c2|command\s*and\s*control|browser\s*hijack|search\s*manipulation|payload\s*injection|"
    r"remote\s*payload|tab\s*url|url\s*exfil|steganograph|png\s*icon|offscreen|"
    r"darkspectre|ghostposter|reddirection|spyvpn|greedybear|foxywallet|shadypanda|"
    r"vscode\s*malware|chrome\s*web\s*store|firefox\s*extension)\b",
    re.IGNORECASE,
)


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"})
    return s


def fetch_html(url: str, session: requests.Session | None = None) -> str | None:
    s = session or _session()
    try:
        r = s.get(url, timeout=30)
        r.raise_for_status()
        return r.text
    except Exception:
        return None


def get_blog_post_links(html: str, base_url: str) -> list[tuple[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    out = []
    seen = set()
    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href:
            continue
        if not href.startswith("http"):
            href = urljoin(base_url, href)
        parsed = urlparse(href)
        path = parsed.path.rstrip("/")
        if "/blog/" not in path or path == "/blog" or path.count("/") < 2:
            continue
        if href in seen:
            continue
        seen.add(href)
        title = (a.get_text() or "").strip()[:200]
        if not title and a.find_parent(["h1", "h2", "h3", "h4"]):
            title = (a.find_parent(["h1", "h2", "h3", "h4"]) or a).get_text().strip()[:200]
        out.append((title or path.split("/")[-1] or "unknown", href))
    return out


def is_extension_analysis_post(title: str, url: str, snippet: str = "") -> bool:
    text = (title + " " + url + " " + snippet).lower()
    keywords = (
        "extension", "chrome", "browser", "vscode", "vs code", "firefox", "malware",
        "malicious", "infected", "campaign", "hijack", "steal", "darkspectre",
        "ghostposter", "reddirection", "spyvpn", "vk styles", "greedybear", "foxywallet",
        "shadypanda", "marketplace", "web store", "add-in", "outlook", "mcp",
        "steganograph", "cryptojack", "screen capture", "2.3 million", "trusted them",
    )
    return any(k in text for k in keywords)


def extract_extension_ids(text: str) -> list[str]:
    return list(dict.fromkeys(EXTENSION_ID_RE.findall(text)))


def extract_domains(text: str) -> list[str]:
    candidates = DOMAIN_RE.findall(text)
    skip = {
        "koi.ai", "www.koi.ai", "blog.koi.security", "chromewebstore.google.com",
        "microsoft.com", "google.com", "github.com", "wikipedia.org", "example.com",
        "medium.com", "linkedin.com",
    }
    return [d for d in dict.fromkeys(candidates) if d.lower() not in skip]


def extract_behavior_mentions(text: str) -> list[str]:
    return list(dict.fromkeys(BEHAVIOR_KEYWORDS.findall(text)))


def extract_code_snippets(soup: BeautifulSoup) -> list[str]:
    snippets = []
    for tag in soup.find_all(["pre", "code"]):
        t = (tag.get_text() or "").strip()
        if len(t) > 20 and len(t) < 50000:
            snippets.append(t)
    return snippets


def extract_code_image_urls(soup: BeautifulSoup, page_url: str) -> list[str]:
    """
    Best-effort collection of code-relevant images from the article body
    for Bablu to review (code screenshots, payload diagrams, DevTools, etc.).
    """
    urls: list[str] = []

    article = soup.find("article")
    if article is None:
        article = soup.find("div", class_=re.compile(r"(content|entry-content|post-content)", re.IGNORECASE))

    img_tags = (article or soup).find_all("img", src=True)
    for img in img_tags:
        src = (img.get("src") or "").strip()
        if not src:
            continue
        full = urljoin(page_url, src)
        if full not in urls:
            urls.append(full)

    return urls


def extract_tables(soup: BeautifulSoup) -> list[list[list[str]]]:
    out = []
    for table in soup.find_all("table"):
        rows = []
        for tr in table.find_all("tr"):
            cells = [td.get_text(strip=True) for td in tr.find_all(["td", "th"])]
            if cells:
                rows.append(cells)
        if rows:
            out.append(rows)
    return out


def parse_post(html: str, url: str, title: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(separator="\n")
    extension_ids = extract_extension_ids(text)
    for table in extract_tables(soup):
        for row in table:
            for cell in row:
                extension_ids.extend(extract_extension_ids(cell))
    extension_ids = list(dict.fromkeys(extension_ids))
    domains = extract_domains(text)
    behavior_mentions = extract_behavior_mentions(text)
    snippets = extract_code_snippets(soup)
    code_image_urls = extract_code_image_urls(soup, url)
    return {
        "source_url": url,
        "title": title,
        "extension_ids": extension_ids,
        "domains": domains,
        "behavior_mentions": behavior_mentions,
        "code_snippets_count": len(snippets),
        "code_snippet_previews": [s[:500] for s in snippets[:5]],
        "code_image_urls": code_image_urls,
    }


def crawl(max_posts: int = 50, dry_run: bool = False) -> list[dict]:
    session = _session()
    index_html = fetch_html(BLOG_INDEX_URL, session)
    if not index_html:
        print("[!] Failed to fetch blog index")
        return []
    links = get_blog_post_links(index_html, "https://www.koi.ai")
    candidate_links = [(t, u) for t, u in links if is_extension_analysis_post(t, u)]
    if not candidate_links:
        candidate_links = links[: max_posts * 2]
    else:
        candidate_links = candidate_links[:max_posts]
    print(f"[+] Found {len(links)} blog links, {len(candidate_links)} extension-related")
    results = []
    for i, (title, url) in enumerate(candidate_links):
        if i >= max_posts:
            break
        if dry_run:
            print(f"  [dry-run] {url}")
            results.append({"source_url": url, "title": title, "extension_ids": [], "domains": [], "behavior_mentions": []})
            continue
        html = fetch_html(url, session)
        if not html:
            print(f"  [!] Skip (fetch failed): {url}")
            continue
        parsed = parse_post(html, url, title)
        results.append(parsed)
        print(f"  [+] {title[:60]}... -> {len(parsed['extension_ids'])} IDs, {len(parsed['domains'])} domains")
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description="K blog crawler — extension analysis IOCs and lessons")
    ap.add_argument("--max-posts", type=int, default=30, help="Max extension-related posts to fetch")
    ap.add_argument("--dry-run", action="store_true", help="Only list URLs, do not fetch posts")
    ap.add_argument("--output-dir", type=Path, default=REPO_ROOT / "data" / "k", help="Output directory for JSON")
    ap.add_argument("--write-lessons", action="store_true", help="Update docs/K_LESSONS_LEARNT.md")
    args = ap.parse_args()

    print("[K] Crawling blog index...", flush=True)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    results = crawl(max_posts=args.max_posts, dry_run=args.dry_run)
    if not results:
        sys.exit(1)

    all_ids = list(dict.fromkeys(i for p in results for i in p.get("extension_ids", [])))
    all_domains = list(dict.fromkeys(d for p in results for d in p.get("domains", [])))
    consolidated = {
        "extension_ids": all_ids,
        "domains": all_domains,
        "posts": [{"title": p.get("title"), "url": p.get("source_url"), "extension_ids": p.get("extension_ids", []), "domains": p.get("domains", [])} for p in results],
    }

    if not args.dry_run:
        (args.output_dir / "k_posts.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
        (args.output_dir / "k_consolidated.json").write_text(json.dumps(consolidated, indent=2), encoding="utf-8")
        print(f"\n[i] Wrote {args.output_dir / 'k_posts.json'} and k_consolidated.json")
        print(f"[i] Total extension IDs: {len(all_ids)}, domains: {len(all_domains)}")

    if args.write_lessons and not args.dry_run:
        lessons_path = REPO_ROOT / "docs" / "K_LESSONS_LEARNT.md"
        _write_lessons(lessons_path, results, consolidated)
        print(f"[i] Updated {lessons_path}")


def _write_lessons(path: Path, results: list[dict], consolidated: dict) -> None:
    intro = "# K blog — extension analysis lessons learnt\n\n"
    intro += "Populated by `scripts/k_crawler.py`. Use with Bablu and the detection library.\n\n"
    lines = []
    lines.append("## Consolidated IOCs (crawler)\n")
    lines.append("### Extension IDs (Chrome)\n")
    for eid in consolidated.get("extension_ids", [])[:200]:
        lines.append(f"- `{eid}`")
    if len(consolidated.get("extension_ids", [])) > 200:
        lines.append(f"\n*… and {len(consolidated['extension_ids']) - 200} more (see data/k/k_consolidated.json)*\n")
    lines.append("\n### Domains\n")
    for d in consolidated.get("domains", [])[:100]:
        lines.append(f"- `{d}`")
    if len(consolidated.get("domains", [])) > 100:
        lines.append(f"\n*… and {len(consolidated['domains']) - 100} more*\n")
    lines.append("\n### Detection hints from posts\n")
    lines.append("| Post | Extension IDs | Behaviors / campaign |\n|------|---------------|----------------------|\n")
    for p in results[:25]:
        title = (p.get("title") or "")[:55].replace("|", "-")
        url = p.get("source_url", "")
        ids_str = ", ".join(p.get("extension_ids", [])[:3]) or "—"
        behaviors = ", ".join(p.get("behavior_mentions", [])[:3]) or "—"
        lines.append(f"| [{title}]({url}) | {ids_str} | {behaviors} |\n")

    lines.append("\n### Example code snippets (text)\n")
    for p in results[:15]:
        snippets = p.get("code_snippet_previews") or []
        if not snippets:
            continue
        title = (p.get("title") or "")[:55].replace("|", "-")
        url = p.get("source_url", "")
        lines.append(f"- **{title}** ({url})\n")
        for snip in snippets[:3]:
            safe = snip.replace("```", "`\u200b``")
            lines.append("  - ```")
            lines.append(safe)
            lines.append("  ```")

    lines.append("\n### Code snippet images\n")
    for p in results[:25]:
        imgs = p.get("code_image_urls") or []
        if not imgs:
            continue
        title = (p.get("title") or "")[:55].replace("|", "-")
        url = p.get("source_url", "")
        for img in imgs[:3]:
            lines.append(f"- **{title}** ({url}) → {img}")

    lines.append("\n### Bablu / detection library mapping\n")
    lines.append("- **Browser hijacking / tab URL exfil**: RedDirection-style campaigns monitor tab activity and send URLs to C2. Our scanner: tab.url + network sink patterns, host_permissions <all_urls>.\n")
    lines.append("- **Search result manipulation**: Extensions that inject or redirect search; often use remote config. Look for dynamic script/config fetch + DOM injection.\n")
    lines.append("- **Steganography / hidden payload**: Payloads hidden in PNG or canvas; we flag offscreen usage, canvas steganography, and captureVisibleTab.\n")
    lines.append("- **Extension IDs above**: Add to IOC database or blocklist. **Domains above**: Add to domain intelligence.\n")
    new_content = intro + "\n".join(lines)
    if path.exists():
        existing = path.read_text(encoding="utf-8")
        idx = existing.find("## Consolidated IOCs (crawler)")
        if idx != -1:
            after = existing[idx:]
            next_h2 = after.find("\n## ", 1)
            rest = after[next_h2:].lstrip() if next_h2 != -1 else ""
            before = existing[:idx].rstrip()
            new_content = before + "\n\n" + new_content.strip() + ("\n\n" + rest if rest else "")
    path.write_text(new_content, encoding="utf-8")


if __name__ == "__main__":
    main()
