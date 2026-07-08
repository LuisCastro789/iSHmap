"""
Simple scripting engine (iSHMap Scripting Engine, ISE) -- an nmap
NSE-inspired plugin system.

Scripts are plain Python files placed in the `scripts/` directory
that expose a coroutine `run(ip, open_ports, context) -> dict`.
This keeps the engine dependency-free (no Lua runtime needed on iSH)
while still letting users extend scan behavior, e.g. add custom
banner checks, CVE hints, or default-credential probes.
"""
import asyncio
import importlib.util
import os

SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "..", "scripts")


def load_scripts():
    scripts = {}
    if not os.path.isdir(SCRIPTS_DIR):
        return scripts
    for fname in os.listdir(SCRIPTS_DIR):
        if fname.endswith(".py") and not fname.startswith("_"):
            path = os.path.join(SCRIPTS_DIR, fname)
            spec = importlib.util.spec_from_file_location(fname[:-3], path)
            mod = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(mod)
                if hasattr(mod, "run"):
                    scripts[fname[:-3]] = mod.run
            except Exception:
                continue
    return scripts


async def run_scripts(ip, open_ports, script_names=None, context=None):
    scripts = load_scripts()
    if script_names:
        scripts = {k: v for k, v in scripts.items() if k in script_names}
    results = {}
    for name, fn in scripts.items():
        try:
            results[name] = await fn(ip, open_ports, context or {})
        except Exception as e:
            results[name] = {"error": str(e)}
    return results
