"""A small bounded LRU cache."""
from collections import OrderedDict
from typing import Generic, Hashable, TypeVar

V = TypeVar("V")


class LRU(Generic[V]):
    def __init__(self, capacity: int = 128) -> None:
        if capacity < 1:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self._data: OrderedDict[Hashable, V] = OrderedDict()

    def get(self, key: Hashable, default: V | None = None) -> V | None:
        if key not in self._data:
            return default
        self._data.move_to_end(key)
        return self._data[key]

    def put(self, key: Hashable, value: V) -> None:
        self._data[key] = value
        self._data.move_to_end(key)
        while len(self._data) > self.capacity:
            self._data.popitem(last=False)

    def __len__(self) -> int:
        return len(self._data)
