"""The narrow-only scope rule for scans requested from the serve UI.

`kubedelos serve` runs with a configured scope (namespaces, exclusions, selectors, package types). A scan
requested from the UI may only narrow that scope, never widen it, so opening writes does not let a viewer
scan what the operator excluded. This is a pure comparison of two `Settings`, with no I/O.
"""

from kubedelos.config import Settings


def outside_scope(configured: Settings, requested: Settings) -> str | None:
    """Return the first way `requested` goes beyond `configured`, or None when it is inside."""
    if configured.namespaces:
        if not requested.namespaces:  # empty reaches the scanner as "all namespaces"
            return "namespaces must stay inside the configured scope"
        for namespace in requested.namespaces:
            if namespace not in configured.namespaces:
                return f"namespace {namespace} is outside the configured scope"
    else:
        for namespace in requested.namespaces:
            if namespace in configured.exclude_namespaces:
                return f"namespace {namespace} is outside the configured scope"
    for namespace in configured.exclude_namespaces:
        if namespace not in requested.exclude_namespaces:
            return f"namespace {namespace} is excluded by the configured scope"
    for pattern in configured.exclude_images:
        if pattern not in requested.exclude_images:
            return f"image exclusion {pattern} is part of the configured scope"
    if configured.namespace_selector is not None and requested.namespace_selector != configured.namespace_selector:
        return f"namespace selector must stay {configured.namespace_selector}"
    if configured.selector is not None and requested.selector != configured.selector:
        return f"label selector must stay {configured.selector}"
    for pkg_type in requested.pkg_types:
        if pkg_type not in configured.pkg_types:
            return f"package type {pkg_type} is not in the configured scope"
    return None
