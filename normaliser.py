#!/usr/bin/env python3
import sys, copy, yaml

def deep_merge(base, override):
    if isinstance(base, dict) and isinstance(override, dict):
        out = copy.deepcopy(base)
        for k, v in override.items():
            if k in out:
                out[k] = deep_merge(out[k], v)
            else:
                out[k] = copy.deepcopy(v)
        return out
    # lists: override wins (compose semantics vary; this is the safer choice)
    return copy.deepcopy(override)

def resolve_extends(doc):
    services = doc.get("services", {})
    # allow multiple passes in case of chained extends
    changed = True
    while changed:
        changed = False
        for name, svc in list(services.items()):
            ext = svc.get("extends")
            if not ext:
                continue
            base_name = ext["service"] if isinstance(ext, dict) else ext
            base = services.get(base_name)
            if not base:
                continue
            merged = deep_merge(base, {k:v for k,v in svc.items() if k != "extends"})
            services[name] = merged
            changed = True
    doc["services"] = services
    return doc

def ensure_defaults(doc):
    for name, svc in (doc.get("services") or {}).items():
        # logging defaults
        if "logging" not in svc:
            svc["logging"] = {"driver": "json-file", "options": {}}
        else:
            svc["logging"].setdefault("driver", "json-file")
            svc["logging"].setdefault("options", {})

        # restart default
        svc.setdefault("restart", "no")

        # security/caps defaults
        svc.setdefault("cap_add", [])
        svc.setdefault("cap_drop", [])
        svc.setdefault("security_opt", [])

        # ports default (no published ports)
        svc.setdefault("ports", [])

        # healthcheck defaults (only if healthcheck present)
        hc = svc.get("healthcheck")
        if isinstance(hc, dict):
            hc.setdefault("interval", "30s")
            hc.setdefault("timeout", "30s")
            hc.setdefault("retries", 3)
            hc.setdefault("start_period", "0s")

        # volumes read_only default (convert long-syntax only)
        vols = svc.get("volumes")
        if isinstance(vols, list):
            new_vols = []
            for v in vols:
                if isinstance(v, dict):
                    v.setdefault("read_only", False)
                # string short-syntax: leave as-is (recommend normalizing via `podman-compose config` first)
                new_vols.append(v)
            svc["volumes"] = new_vols

        # tmpfs defaults (no change if absent)
        # networks: leave as-is

    return doc

def main():
    data = yaml.safe_load(sys.stdin.read())
    data = resolve_extends(data)
    data = ensure_defaults(data)
    yaml.safe_dump(data, sys.stdout, sort_keys=False)

if __name__ == "__main__":
    main()
