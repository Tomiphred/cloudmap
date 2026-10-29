"""Contract every cloud provider implements."""
from __future__ import annotations

import argparse
from abc import ABC, abstractmethod
from typing import Callable

from ..model import Graph


class Provider(ABC):
    name: str = ""

    def __init__(self, log: Callable[[str], None] | None = None):
        self.log = log or (lambda _msg: None)

    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser) -> None:
        """Register provider-specific CLI flags."""

    @classmethod
    @abstractmethod
    def from_args(cls, args: argparse.Namespace, log: Callable[[str], None]) -> "Provider":
        ...

    @abstractmethod
    def discover(self) -> Graph:
        """Read (never modify) the environment and return a finalized Graph."""
