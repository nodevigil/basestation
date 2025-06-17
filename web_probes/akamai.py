def probe(address: str, port: int = 80, timeout: int = 5) -> dict:
    """
    Detects Akamai on the given host/port. Returns a result dict if found, else None.
    """
    import requests
    try:
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{address}:{port}"
        resp = requests.get(url, timeout=timeout)
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        if "akamai" in headers or "x-akamai-transformed" in headers:
            return {
                "detected": True,
                "vendor": "Akamai",
                "headers": {k: v for k, v in resp.headers.items() if "akamai" in k.lower()},
                "status_code": resp.status_code,
            }
        if "akamai" in resp.text.lower() or "akamai" in resp.reason.lower():
            return {
                "detected": True,
                "vendor": "Akamai",
                "match": "body",
                "status_code": resp.status_code,
            }
    except Exception as e:
        return {"error": str(e)}
    return None

