"""A tiny in-memory inventory with validated quantities."""
from dataclasses import dataclass, field


@dataclass
class Item:
    sku: str
    name: str
    quantity: int = 0


@dataclass
class Inventory:
    items: dict[str, Item] = field(default_factory=dict)

    def add(self, sku: str, name: str, quantity: int) -> Item:
        if quantity < 0:
            raise ValueError("quantity must not be negative")
        item = self.items.setdefault(sku, Item(sku, name))
        item.quantity += quantity
        return item

    def remove(self, sku: str, quantity: int) -> Item:
        item = self.items[sku]
        if quantity > item.quantity:
            raise ValueError(f"only {item.quantity} of {sku} in stock")
        item.quantity -= quantity
        return item

    def low_stock(self, threshold: int = 5) -> list[Item]:
        return sorted((i for i in self.items.values() if i.quantity <= threshold), key=lambda i: i.sku)
