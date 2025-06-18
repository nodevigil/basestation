def probe(address: str, port: int = 80, timeout: int = 5) -> dict:
    """
    Detects Cloudflare on the given host/port. Returns a result dict if found, else None.
    """
    import requests
    try:
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{address}:{port}"
        resp = requests.get(url, timeout=timeout)
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        if (
            ("server" in headers and "cloudflare" in headers["server"])
            or any(h in headers for h in ["cf-ray", "cf-cache-status", "cf-request-id"])
        ):
            return {
                "detected": True,
                "vendor": "Cloudflare",
                "headers": {k: v for k, v in resp.headers.items() if k.lower().startswith("cf-") or k.lower() == "server"},
                "status_code": resp.status_code,
            }
    except Exception as e:
        return {"detected": False}
    return {"detected": False}

