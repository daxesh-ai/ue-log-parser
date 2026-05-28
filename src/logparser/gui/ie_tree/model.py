"""IE Tree model — displays fully decoded Information Elements.

Uses the decoded_tree (dict/tuple from pycrate get_val() with inner containers
decoded) to build a hierarchical Qt tree matching QCAT-style output.
"""

from __future__ import annotations

try:
    from PySide6.QtCore import QAbstractItemModel, QModelIndex, Qt
except ImportError:
    from PyQt6.QtCore import QAbstractItemModel, QModelIndex, Qt

from logparser.core.message import ParsedMessage


class TreeNode:
    __slots__ = ("name", "value", "children", "parent", "row")

    def __init__(self, name: str, value: str = "", parent: "TreeNode | None" = None, row: int = 0):
        self.name = name
        self.value = value
        self.children: list[TreeNode] = []
        self.parent = parent
        self.row = row

    def child_count(self) -> int:
        return len(self.children)


def _build_tree(data, name: str = "root", parent: TreeNode | None = None, row: int = 0) -> TreeNode:
    """Recursively build a TreeNode from pycrate decoded output.

    Handles:
    - dict → SEQUENCE (field names as children)
    - tuple(str, val) → CHOICE (alternative name + value)
    - list → SEQUENCE OF (indexed items)
    - bytes → hex display
    - int/str/bool → leaf values
    """
    node = TreeNode(name=name, parent=parent, row=row)

    if isinstance(data, dict):
        for i, (key, val) in enumerate(data.items()):
            child = _build_tree(val, name=str(key), parent=node, row=i)
            node.children.append(child)

    elif isinstance(data, tuple):
        if len(data) == 2 and isinstance(data[0], str):
            # CHOICE: (alternative_name, value)
            alt_name = data[0]
            alt_val = data[1]
            # If the value is complex, show choice name as a branch
            if isinstance(alt_val, (dict, list, tuple)):
                child = _build_tree(alt_val, name=alt_name, parent=node, row=0)
                node.children.append(child)
            else:
                # Simple value choice - show inline
                node.value = f"{alt_name}: {alt_val}"
        elif len(data) == 2 and isinstance(data[0], int):
            # BIT STRING: (integer_value, bit_length)
            int_val, bit_len = data
            if bit_len <= 64:
                node.value = f"{int_val} ({bit_len} bits, 0x{int_val:X})"
            else:
                node.value = f"({bit_len} bits) 0x{int_val:X}"
        else:
            # Unknown tuple
            node.value = str(data)

    elif isinstance(data, list):
        for i, item in enumerate(data):
            child = _build_tree(item, name=f"Item {i}", parent=node, row=i)
            node.children.append(child)

    elif isinstance(data, bytes):
        hex_str = data.hex()
        if len(hex_str) > 80:
            node.value = f"{hex_str[:80]}... ({len(data)} bytes)"
        else:
            node.value = hex_str

    elif isinstance(data, bool):
        node.value = "TRUE" if data else "FALSE"

    elif isinstance(data, int):
        if abs(data) > 0xFFFF:
            node.value = f"{data} (0x{data:X})"
        elif abs(data) > 255:
            node.value = f"{data}"
        else:
            node.value = str(data)

    elif data is None:
        node.value = "NULL"

    else:
        node.value = str(data)

    return node


class IETreeModel(QAbstractItemModel):
    """Qt tree model for displaying decoded Information Elements."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._root: TreeNode | None = None

    def set_message(self, msg: ParsedMessage | None) -> None:
        self.beginResetModel()
        if msg and msg.decoded_tree is not None:
            # Use decoded_tree (has inner containers decoded)
            self._root = _build_tree(msg.decoded_tree, name=msg.summary)
        else:
            self._root = None
        self.endResetModel()

    def index(self, row: int, column: int, parent=QModelIndex()) -> QModelIndex:
        if not self.hasIndex(row, column, parent):
            return QModelIndex()

        parent_node = self._node_from_index(parent)
        if parent_node and row < len(parent_node.children):
            return self.createIndex(row, column, parent_node.children[row])
        return QModelIndex()

    def parent(self, index: QModelIndex) -> QModelIndex:
        if not index.isValid():
            return QModelIndex()
        node: TreeNode = index.internalPointer()
        if node.parent is None or node.parent == self._root:
            return QModelIndex()
        return self.createIndex(node.parent.row, 0, node.parent)

    def rowCount(self, parent=QModelIndex()) -> int:
        node = self._node_from_index(parent)
        return node.child_count() if node else 0

    def columnCount(self, parent=QModelIndex()) -> int:
        return 2  # Name | Value

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        node: TreeNode = index.internalPointer()
        if index.column() == 0:
            return node.name
        elif index.column() == 1:
            return node.value
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return ["IE Name", "Value"][section]
        return None

    def _node_from_index(self, index: QModelIndex) -> TreeNode | None:
        if index.isValid():
            return index.internalPointer()
        return self._root
