"""
PROXSYNTH PROXY AUTO-ENFORCEMENT RUNTIME HOOK (sitecustomize.py)
--------------------------------------------------------------
Auto-executed by Python's `site` module on startup before any script runs.
Guarantees that all outbound HTTP/HTTPS traffic from AI Agent scripts
(requests, httpx, urllib, aiohttp) routes through Proxynth Forward Proxy (:8088),
with zero manual configuration required in the agent's code.
"""
import os
import sys

# Do not intercept if explicitly disabled or inside Proxynth Proxy server process itself
disable_proxy = os.environ.get("PROXSYNTH_DISABLE_AUTO_PROXY", "0") == "1"
is_proxy = os.environ.get("PROXSYNTH_IS_PROXY", "0") == "1"

if not disable_proxy and not is_proxy:
    proxy_port = int(os.environ.get("PROXSYNTH_PROXY_PORT", "8088"))
    proxy_url = os.environ.get("PROXSYNTH_PROXY_URL", f"http://127.0.0.1:{proxy_port}")

    # 1. Inject Standard Proxy Environment Variables
    os.environ["HTTP_PROXY"] = proxy_url
    os.environ["HTTPS_PROXY"] = proxy_url
    os.environ["http_proxy"] = proxy_url
    os.environ["https_proxy"] = proxy_url
    os.environ["ALL_PROXY"] = proxy_url
    os.environ["all_proxy"] = proxy_url

    # 2. Configure Proxsynth Root CA Certificate & Disable Verification Warnings
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    ca_path = ""
    for _ in range(5):
        for ca_dir_name, crt_name in [(".proxsynth_ca", "proxsynth_ca.crt"), (".proxynth_ca", "proxynth_ca.crt")]:
            candidate = os.path.join(curr_dir, ca_dir_name, crt_name)
            if os.path.exists(candidate):
                ca_path = os.path.abspath(candidate)
                break
        if ca_path:
            break
        parent = os.path.dirname(curr_dir)
        if parent == curr_dir:
            break
        curr_dir = parent

    if ca_path and os.path.exists(ca_path):
        os.environ["REQUESTS_CA_BUNDLE"] = ca_path
        os.environ["SSL_CERT_FILE"] = ca_path
        os.environ["CURL_CA_BUNDLE"] = ca_path

    os.environ["PYTHONHTTPSVERIFY"] = "0"
    os.environ["CURL_INSECURE"] = "1"
    os.environ["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"

    # Suppress SSL Insecure Request Warnings
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    # Rotating legitimate desktop browser User-Agents pool
    _LEGITIMATE_UAS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
    ]
    import random
    def _get_legit_ua():
        return random.choice(_LEGITIMATE_UAS)

    def _inject_browser_headers(headers_dict):
        """Injects legitimate modern browser User-Agent, matching Client Hints, and Proxsynth correlation headers."""
        try:
            from backend.user_agents import get_random_browser_profile
            prof = get_random_browser_profile()
            headers_dict["User-Agent"] = prof["user_agent"]
            if prof.get("sec_ch_ua"):
                headers_dict["Sec-Ch-Ua"] = prof["sec_ch_ua"]
                headers_dict["Sec-Ch-Ua-Mobile"] = prof["sec_ch_ua_mobile"]
                headers_dict["Sec-Ch-Ua-Platform"] = prof["sec_ch_ua_platform"]
        except Exception:
            headers_dict["User-Agent"] = _get_legit_ua()

        prox_proj = os.environ.get("PROXSYNTH_PROJECT") or os.environ.get("PROXSYNTH_PROJECT")
        prox_agent = os.environ.get("PROXSYNTH_AGENT_ID") or os.environ.get("PROXSYNTH_AGENT_ID")
        if prox_proj:
            headers_dict["X-Proxsynth-Project"] = prox_proj
            headers_dict["X-Proxynth-Project"] = prox_proj
        if prox_agent:
            headers_dict["X-Proxsynth-Agent"] = prox_agent
            headers_dict["X-Proxynth-Agent"] = prox_agent

    # 3. Patch `requests` library to guarantee proxy routing and legitimate browser User-Agent
    try:
        import requests
        _orig_session_init = requests.Session.__init__
        def _proxsynth_session_init(self, *args, **kwargs):
            _orig_session_init(self, *args, **kwargs)
            if not getattr(self, "proxies", None):
                self.proxies = {
                    "http": proxy_url,
                    "https": proxy_url
                }
            if getattr(self, "verify", None) is True:
                self.verify = False
            # Inject rotating legitimate browser User-Agent and Client Hints if missing or default python-requests
            curr_ua = self.headers.get("User-Agent", "") if getattr(self, "headers", None) else ""
            if not curr_ua or "python" in curr_ua.lower():
                _inject_browser_headers(self.headers)
        requests.Session.__init__ = _proxsynth_session_init
    except Exception:
        pass

    # 4. Patch `httpx` library if available
    try:
        import httpx
        _orig_httpx_init = httpx.Client.__init__
        def _proxsynth_httpx_init(self, *args, **kwargs):
            if "proxy" not in kwargs and "proxies" not in kwargs:
                kwargs["proxy"] = proxy_url
            if "verify" not in kwargs:
                kwargs["verify"] = False
            hdrs = kwargs.get("headers")
            if hdrs is None:
                new_hdrs = {}
                _inject_browser_headers(new_hdrs)
                kwargs["headers"] = new_hdrs
            elif isinstance(hdrs, dict):
                curr_ua = hdrs.get("User-Agent") or hdrs.get("user-agent", "")
                if not curr_ua or "python" in curr_ua.lower() or "httpx" in curr_ua.lower():
                    _inject_browser_headers(hdrs)
            _orig_httpx_init(self, *args, **kwargs)
        httpx.Client.__init__ = _proxsynth_httpx_init

        if hasattr(httpx, "AsyncClient"):
            _orig_async_init = httpx.AsyncClient.__init__
            def _proxsynth_async_init(self, *args, **kwargs):
                if "proxy" not in kwargs and "proxies" not in kwargs:
                    kwargs["proxy"] = proxy_url
                if "verify" not in kwargs:
                    kwargs["verify"] = False
                hdrs = kwargs.get("headers")
                if hdrs is None:
                    new_hdrs = {}
                    _inject_browser_headers(new_hdrs)
                    kwargs["headers"] = new_hdrs
                elif isinstance(hdrs, dict):
                    curr_ua = hdrs.get("User-Agent") or hdrs.get("user-agent", "")
                    if not curr_ua or "python" in curr_ua.lower() or "httpx" in curr_ua.lower():
                        _inject_browser_headers(hdrs)
                _orig_async_init(self, *args, **kwargs)
            httpx.AsyncClient.__init__ = _proxsynth_async_init
    except Exception:
        pass

    # 5. Patch `urllib.request` standard library
    try:
        import urllib.request
        _proxy_handler = urllib.request.ProxyHandler({
            "http": proxy_url,
            "https": proxy_url
        })
        _opener = urllib.request.build_opener(_proxy_handler)
        _headers_to_add = [("User-Agent", _get_legit_ua())]
        try:
            from backend.user_agents import get_random_browser_profile
            prof = get_random_browser_profile()
            _headers_to_add = [("User-Agent", prof["user_agent"])]
            if prof.get("sec_ch_ua"):
                _headers_to_add.append(("Sec-Ch-Ua", prof["sec_ch_ua"]))
                _headers_to_add.append(("Sec-Ch-Ua-Mobile", prof["sec_ch_ua_mobile"]))
                _headers_to_add.append(("Sec-Ch-Ua-Platform", prof["sec_ch_ua_platform"]))
        except Exception:
            pass
        _opener.addheaders = _headers_to_add
        urllib.request.install_opener(_opener)
    except Exception:
        pass

    # 6. Patch `aiohttp` library if available
    try:
        import aiohttp
        _orig_aiohttp_init = aiohttp.ClientSession.__init__
        def _proxsynth_aiohttp_init(self, *args, **kwargs):
            if "trust_env" not in kwargs:
                kwargs["trust_env"] = True
            hdrs = kwargs.get("headers")
            if hdrs is None:
                new_hdrs = {}
                _inject_browser_headers(new_hdrs)
                kwargs["headers"] = new_hdrs
            elif isinstance(hdrs, dict):
                curr_ua = hdrs.get("User-Agent") or hdrs.get("user-agent", "")
                if not curr_ua or "python" in curr_ua.lower() or "aiohttp" in curr_ua.lower():
                    _inject_browser_headers(hdrs)
            _orig_aiohttp_init(self, *args, **kwargs)
        aiohttp.ClientSession.__init__ = _proxsynth_aiohttp_init
    except Exception:
        pass
