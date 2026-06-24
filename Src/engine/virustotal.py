# src/engine/virustotal.py
import hashlib
import requests
import base64
from config import VIRUSTOTAL_API_KEY


def check(url: str, api_key: str = "") -> dict:
    """
    Query VirusTotal for a URL.
    Returns: { hits: int, total: int, available: bool, link: str }
    """
    key = api_key or VIRUSTOTAL_API_KEY
    if not key:
        return {"hits": 0, "total": 0, "available": False, "link": ""}

    try:
        url_id  = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": key}
        resp    = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=8
        )

        if resp.status_code == 200:
            data  = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            hits  = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values())
            link  = f"https://www.virustotal.com/gui/url/{url_id}/detection"
            return {"hits": hits, "total": total, "available": True, "link": link}

        elif resp.status_code == 404:
            # URL not in VT database yet — submit it
            requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers, data={"url": url}, timeout=8
            )
            return {"hits": 0, "total": 0, "available": True, "link": ""}

    except Exception:
        pass

    return {"hits": 0, "total": 0, "available": False, "link": ""}