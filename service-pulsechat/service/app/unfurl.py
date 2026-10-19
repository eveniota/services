import re
import urllib.parse
import httpx

BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}


def is_safe_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False
        if hostname in BLOCKED_HOSTS:
            return False
        return True
    except Exception:
        return False


async def fetch_url_preview(url: str) -> dict:
    if not is_safe_url(url):
        return {"error": "Target URL is blocked by security policy", "url": url}

    try:
        async with httpx.AsyncClient(timeout=3.0, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "PulseChat-Bot/1.0"})
            content_type = resp.headers.get("content-type", "").lower()

            if "application/json" in content_type:
                try:
                    data = resp.json()
                    return {
                        "url": url,
                        "title": data.get("title") or data.get("name") or "API Endpoint",
                        "description": str(data.get("topic") or data.get("description") or data)[:200],
                        "status_code": resp.status_code
                    }
                except Exception:
                    pass

            text = resp.text[:10000]
            title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
            title = title_match.group(1).strip() if title_match else "Website Preview"

            desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\'](.*?)["\']', text, re.IGNORECASE)
            description = desc_match.group(1).strip() if desc_match else ""

            return {
                "url": url,
                "title": title[:100],
                "description": description[:200],
                "status_code": resp.status_code
            }
    except Exception as e:
        return {"error": f"Preview generation failed: {str(e)}", "url": url}
