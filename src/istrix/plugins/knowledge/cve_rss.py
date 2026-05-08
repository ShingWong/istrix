"""NVD RSS Feed poller — fetches CVE updates from NVD feeds and stores in database.

Uses the NVD CVE API and optional RSS feeds to keep the local CVE database current.
Runs as a scheduled task in the job pipeline.
"""

import feedparser
from dataclasses import dataclass


NVD_RSS_URLS = [
    "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
    "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",
]


@dataclass
class FeedEntry:
    cve_id: str
    title: str
    summary: str = ""
    cvss: float = 0.0
    published: str = ""
    url: str = ""


async def fetch_nvd_rss(url: str = "") -> list[FeedEntry]:
    """Fetch CVE entries from an NVD RSS feed URL.

    Returns a list of FeedEntry objects. Falls back gracefully
    if the feed is unavailable (network error, parse error).
    """
    urls = [url] if url else NVD_RSS_URLS
    entries: list[FeedEntry] = []
    seen: set[str] = set()

    for feed_url in urls:
        try:
            feed = feedparser.parse(feed_url)
        except Exception:
            continue

        for item in feed.entries:
            cve_id = _extract_cve_id(item.get("title", ""))
            if not cve_id or cve_id in seen:
                continue
            seen.add(cve_id)

            summary = item.get("summary", item.get("description", ""))
            entries.append(FeedEntry(
                cve_id=cve_id,
                title=item.get("title", cve_id),
                summary=_strip_html(summary)[:500],
                published=item.get("published", ""),
                url=item.get("link", ""),
            ))

    return entries


async def poll_cve_feeds() -> list[FeedEntry]:
    """Poll all configured NVD RSS feeds for new CVE entries.

    This is the main entry point called by the scheduler.
    """
    return await fetch_nvd_rss()


def _extract_cve_id(text: str) -> str:
    """Extract CVE-YYYY-NNNNN from text."""
    import re
    m = re.search(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)
    return m.group(0) if m else ""


def _strip_html(text: str) -> str:
    """Strip HTML tags from text."""
    import re
    return re.sub(r"<[^>]+>", "", text)
