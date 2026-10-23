"""
Proxsynth - Legitimate Browser User-Agent Rotation Engine
Maintains modern, realistic browser fingerprint profiles (Chrome, Edge, Safari, Firefox
on Windows, macOS, and Linux) to prevent anti-bot and WAF fingerprint blocking.
"""

import random
from typing import Dict, Any, Optional, Tuple

# Modern browser User-Agent profiles (Chrome 129+, Edge 129+, Safari 17+, Firefox 131+)
BROWSER_PROFILES = [
    {
        "browser": "Chrome",
        "os": "Windows",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        "sec_ch_ua_platform": '"Windows"',
        "sec_ch_ua_mobile": "?0"
    },
    {
        "browser": "Chrome",
        "os": "Windows",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
        "sec_ch_ua_platform": '"Windows"',
        "sec_ch_ua_mobile": "?0"
    },
    {
        "browser": "Chrome",
        "os": "macOS",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        "sec_ch_ua_platform": '"macOS"',
        "sec_ch_ua_mobile": "?0"
    },
    {
        "browser": "Edge",
        "os": "Windows",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
        "sec_ch_ua": '"Microsoft Edge";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        "sec_ch_ua_platform": '"Windows"',
        "sec_ch_ua_mobile": "?0"
    },
    {
        "browser": "Safari",
        "os": "macOS",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
        "sec_ch_ua": None,
        "sec_ch_ua_platform": None,
        "sec_ch_ua_mobile": None
    },
    {
        "browser": "Firefox",
        "os": "Windows",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
        "sec_ch_ua": None,
        "sec_ch_ua_platform": None,
        "sec_ch_ua_mobile": None
    },
    {
        "browser": "Chrome",
        "os": "Linux",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        "sec_ch_ua_platform": '"Linux"',
        "sec_ch_ua_mobile": "?0"
    },
    {
        "browser": "Firefox",
        "os": "Linux",
        "user_agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
        "sec_ch_ua": None,
        "sec_ch_ua_platform": None,
        "sec_ch_ua_mobile": None
    }
]

BOT_USER_AGENT_KEYWORDS = [
    "python", "requests", "httpx", "urllib", "aiohttp", "curl", "wget", "go-http-client",
    "java", "postman", "insomnia", "axios", "node-fetch", "proxsynthmcp", "proxynthmcp", "fuzzer", "bot",
    "spider", "crawler", "scanner", "sqlmap", "nmap", "nikto", "nuclei", "gobuster",
    "dirbuster", "ffuf", "hydra", "burp", "zap"
]


DESKTOP_BROWSER_PROFILES = BROWSER_PROFILES


def get_random_browser_profile() -> Dict[str, Any]:
    """Returns a random legitimate browser fingerprint profile."""
    return random.choice(BROWSER_PROFILES)


get_rotating_user_agent = get_random_browser_profile


def get_random_user_agent() -> str:
    """Returns a random modern desktop browser User-Agent string."""
    return random.choice(BROWSER_PROFILES)["user_agent"]


def get_browser_headers(profile: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Returns complete browser headers including Client Hints for the profile."""
    prof = profile or get_random_browser_profile()
    hdrs = {
        "User-Agent": prof["user_agent"],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document"
    }
    if prof.get("sec_ch_ua"):
        hdrs["Sec-Ch-Ua"] = prof["sec_ch_ua"]
        hdrs["Sec-Ch-Ua-Mobile"] = prof["sec_ch_ua_mobile"]
        hdrs["Sec-Ch-Ua-Platform"] = prof["sec_ch_ua_platform"]
    return hdrs


def is_bot_user_agent(user_agent: Optional[str]) -> bool:
    """Detects if a User-Agent is empty, default script engine, or bot-like."""
    if not user_agent or not user_agent.strip():
        return True
    ua_lower = user_agent.lower().strip()
    return any(kw in ua_lower for kw in BOT_USER_AGENT_KEYWORDS)


def apply_rotating_user_agent(
    headers: Dict[str, Any],
    force_rotate: bool = False
) -> Tuple[Dict[str, Any], bool]:
    """
    Ensures headers contain a legitimate browser User-Agent.
    If current User-Agent is bot-like or missing, or if force_rotate=True,
    replaces it with a legitimate modern browser signature and client hints.
    Modifies headers in-place and returns (headers, was_rotated).
    """
    if headers is None:
        headers = {}

    # Case-insensitive lookup for User-Agent
    ua_key = None
    curr_ua = None
    for k, v in list(headers.items()):
        if k.lower() == "user-agent":
            ua_key = k
            curr_ua = str(v)
            break

    should_replace = force_rotate or is_bot_user_agent(curr_ua)

    if should_replace:
        profile = get_random_browser_profile()
        target_key = ua_key if ua_key else "User-Agent"
        headers[target_key] = profile["user_agent"]

        # Inject matching Client Hints if Chrome/Edge
        if profile.get("sec_ch_ua"):
            headers.setdefault("Sec-Ch-Ua", profile["sec_ch_ua"])
            headers.setdefault("Sec-Ch-Ua-Mobile", profile["sec_ch_ua_mobile"])
            headers.setdefault("Sec-Ch-Ua-Platform", profile["sec_ch_ua_platform"])

        # Inject realistic browser Accept and Language headers if missing
        headers.setdefault("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
        headers.setdefault("Accept-Language", "en-US,en;q=0.9")
        headers.setdefault("Sec-Fetch-Site", "none")
        headers.setdefault("Sec-Fetch-Mode", "navigate")
        headers.setdefault("Sec-Fetch-User", "?1")
        headers.setdefault("Sec-Fetch-Dest", "document")
        return headers, True

    return headers, False
