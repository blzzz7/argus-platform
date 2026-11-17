"""Complete controller target lists without changing the simulation backend."""
import sys


def controller_targets(existing, discovery):
    """Preserve generated targets and expand capped Graph discovery when needed."""
    from modules.attack_engine import DOMAIN

    targets = list(existing)
    if discovery and discovery.get("graph_fetch_ok") and discovery.get("real_user_count", 0) >= 200:
        from modules.attack_engine import fetch_tenant_users_from_graph
        ok, users = fetch_tenant_users_from_graph(max_users=sys.maxsize)
        if not ok:
            raise RuntimeError("Complete Graph target discovery failed; retry before running a simulation.")
        targets.extend(users)
    targets.append("victimuser@example.onmicrosoft.com")
    targets.extend(f"fake_user_{i}@{DOMAIN}" for i in range(1, 100))
    return list(dict.fromkeys(targets))
