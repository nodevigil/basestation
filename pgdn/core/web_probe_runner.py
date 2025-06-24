import os
import importlib
import pkgutil

def run_web_probes(address: str, port: int = 80, timeout: int = 5) -> dict:
    """
    Dynamically loads all probe modules in web_probes/ and runs their probe().
    Returns dict {probe_name: result}
    """
    try:
        import pgdn.web_probes as web_probes
        result = {}
        for finder, name, ispkg in pkgutil.iter_modules(web_probes.__path__):
            try:
                module = importlib.import_module(f"pgdn.web_probes.{name}")
                if hasattr(module, "probe"):
                    probe_result = module.probe(address, port, timeout=timeout)
                    result[name] = probe_result if probe_result else {"detected": False}
            except Exception as e:
                result[name] = {"error": f"Failed to load probe {name}: {str(e)}"}
        return result
    except Exception as e:
        return {"error": f"Failed to load web_probes module: {str(e)}"}
    

