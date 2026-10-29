"""Provider registry. Providers are imported lazily so that, for example,
boto3 is only required when you actually scan AWS."""
from __future__ import annotations

import importlib

# name -> (module, class) ; None means "planned, not implemented yet"
_REGISTRY: dict[str, tuple[str, str] | None] = {
    "aws": ("cloudmap.providers.aws", "AWSProvider"),
    "azure": ("cloudmap.providers.azure", "AzureProvider"),
    "gcp": ("cloudmap.providers.gcp", "GCPProvider"),
}


def names() -> list[str]:
    return list(_REGISTRY)


def is_implemented(name: str) -> bool:
    return _REGISTRY.get(name) is not None


def load(name: str):
    entry = _REGISTRY.get(name)
    if entry is None:
        raise NotImplementedError(f"Provider '{name}' is planned but not implemented yet.")
    module, cls = entry
    return getattr(importlib.import_module(module), cls)
