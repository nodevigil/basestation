import os
import importlib
import pkgutil

def run_web_probes(address: str, port: int = 80, timeout: int = 5) -> dict:
    """
    Dynamically loads all probe modules in web_probes/ and runs their probe().
    Returns dict {probe_name: result}
    """
    import web_probes
    result = {}
    for finder, name, ispkg in pkgutil.iter_modules(web_probes.__path__):
        try:
            module = importlib.import_module(f"web_probes.{name}")
            if hasattr(module, "probe"):
                probe_result = module.probe(address, port, timeout=timeout)
                result[name] = probe_result if probe_result else {"detected": False}
        except Exception as e:
            result[name] = {"detected": False}
    return result

