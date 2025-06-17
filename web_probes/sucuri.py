def probe(address: str, port: int = 80, timeout: int = 5) -> dict:
    """
    Detects Sucuri on the given host/port. Returns a result dict if found, else None.
    """
    import requests
    try:
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{address}:{port}"
        resp = requests.get(url, timeout=timeout)
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        if "x-sucuri-id" in headers or "x-sucuri-cache" in headers:
            return {
                "detected": True,
                "vendor": "Sucuri",
                "headers": {k: v for k, v in resp.headers.items() if k.lower().startswith("x-sucuri")},
                "status_code": resp.status_code,
            }
        if "sucuri" in resp.text.lower():
            return {
                "detected": True,
                "vendor": "Sucuri",
                "match": "body",
                "status_code": resp.status_code,
            }
    except Exception as e:
        return {"error": str(e)}
    return None

