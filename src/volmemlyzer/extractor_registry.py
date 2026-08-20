# File: /mnt/data/extractor_registry.py
from __future__ import annotations
import logging
from typing import Dict, Tuple, List, Set, Any, Protocol
from .core import PluginSpec, ExtractResult

log = logging.getLogger(__name__)

class ExtractorFunc(Protocol):
    def __call__(self, json_path: str, *, context: Dict[str, Any]) -> ExtractResult: ...

class ExtractorRegistry:
    """Holds plugin specs and matching extractor callables."""
    def __init__(self):
        self._specs: Dict[str, PluginSpec] = {}
        self._extractors: Dict[str, ExtractorFunc] = {}

    def register(self, spec: PluginSpec, func: ExtractorFunc) -> None:
        if not spec or not func:
            raise ValueError("register() requires a PluginSpec and extractor function")
        key = spec.name.lower()
        self._specs[key] = spec
        self._extractors[key] = func

    def get(self, name: str) -> Tuple[PluginSpec, ExtractorFunc]:
        key = name.lower()
        if key not in self._specs:
            raise KeyError(f"Unknown plugin: {name!r}")
        return self._specs[key], self._extractors[key]

    def has(self, name: str) -> bool:
        key = name.lower()
        return key in self._specs
    
    def names(self) -> List[str]:
        return sorted(self._specs.keys())

    def specs(self) -> List[PluginSpec]:
        return [self._specs[n] for n in self.names()]

    def ready_graph(self, selected: Set[str]) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
        """Dependency edges for `selected`, as (unmet_deps, dependents).

        `unmet_deps[n]` is what n is still waiting on; `dependents[n]` is who is
        waiting on n. A scheduler can then start each plugin as soon as its own
        entry empties, instead of waiting for a whole topological layer to drain.

        Dependencies outside the selection are dropped, matching topo_layers: if
        the caller did not ask for pslist, psscan should still run rather than
        deadlock waiting for it.
        """
        sel = {n.lower() for n in selected}
        unknown = [n for n in sel if n not in self._specs]
        if unknown:
            raise KeyError(f"Unknown plugins in selection: {unknown}")

        unmet: Dict[str, Set[str]] = {n: set(self._specs[n].deps) & sel for n in sel}
        dependents: Dict[str, Set[str]] = {n: set() for n in sel}
        for name, deps in unmet.items():
            for dep in deps:
                dependents[dep].add(name)
        return unmet, dependents

    def cost_sorted(self, names) -> List[str]:
        """Heaviest first, then alphabetical.

        Submission order is start order for a bounded pool, so putting the long
        scanners in first is what keeps the tail short: a heavy plugin started
        last leaves every worker but one idle while it finishes.
        """
        return sorted(names, key=lambda n: (self._specs[n.lower()].cost_rank, n.lower()))

    def topo_layers(self, selected: Set[str]) -> List[Set[str]]:
        """Return dependency layers from the selected plugin names."""
        sel = {n.lower() for n in selected}
        unknown = [n for n in sel if n not in self._specs]
        if unknown:
            raise KeyError(f"Unknown plugins in selection: {unknown}")

        # Build dependency map and indegrees
        deps = {n: set(self._specs[n].deps) & sel for n in sel}
        indeg = {n: len(deps[n]) for n in sel}
        layer = {n for n, d in indeg.items() if d == 0}
        seen: Set[str] = set()
        layers: List[Set[str]] = []
        while layer:
            layers.append(layer)
            seen |= layer
            next_layer: Set[str] = set()
            for n in sel - seen:
                indeg[n] = len(deps[n] - seen)
                if indeg[n] == 0:
                    next_layer.add(n)
            layer = next_layer
        if seen != sel:
            remaining = sel - seen
            raise ValueError(f"Dependency cycle or unresolved deps: {remaining}")
        return layers
