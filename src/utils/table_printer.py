# Python 3.6+
from typing import Any, Dict, Iterable, List, Sequence, Tuple, Optional
from rich.console import Console
from rich.table import Table
from rich import box

_console = Console()

def _coerce_to_rows(
    data: Iterable[Any],
    columns: Optional[List[Tuple[str, str]]] = None,
) -> Tuple[List[Tuple[str, str]], List[List[str]]]:
    """
    Accepts:
      - List[Dict]: columns comes from provided `columns` or keys of first dict
      - List[List]: requires `columns` (labels only used for headers)
    Returns: (columns, rows) where columns = [(key, header), ...]
    """
    data = list(data)
    rows: List[List[str]] = []

    if not data:
        if not columns:
            columns = [("info", "Info")]
        return columns, rows

    first = data[0]

    # Dict mode
    if isinstance(first, dict):
        if columns is None:
            # preserve insertion order of first dict for headers
            columns = [(k, k.replace("_", " ").title()) for k in first.keys()]
        for item in data:
            row = []
            for key, _hdr in columns:
                val = item.get(key, "")
                row.append("" if val is None else str(val))
            rows.append(row)
        return columns, rows

    # List/tuple mode
    if isinstance(first, (list, tuple)):
        if columns is None:
            raise ValueError("When passing a list of lists, you must provide `columns`.")
        for item in data:
            row = ["" if v is None else str(v) for v in item]
            rows.append(row)
        return columns, rows

    raise TypeError("Unsupported data type. Pass List[Dict] or List[List].")


def print_table(
    data: Iterable[Any],
    columns: Optional[List[Tuple[str, str]]] = None,
    title: Optional[str] = None,
    caption: Optional[str] = None,
    sort_by: Optional[str] = None,
    sort_reverse: bool = False,
    style_status: bool = True,
) -> None:
    """
    Pretty-print a table using Rich.

    Args:
        data: List[Dict] or List[List].
        columns: Optional column spec as list of (key, header) tuples.
                 If dicts are provided and columns is None, headers are inferred.
        title: Optional title displayed above the table.
        caption: Optional caption displayed below the table.
        sort_by: Optional key/header to sort by (matches the *key* in columns).
        sort_reverse: Reverse sort.
        style_status: If True, styles cells for keys named 'status', 'ok', or 'failed'.
    """
    cols, rows = _coerce_to_rows(data, columns)

    # Sorting (by key name)
    if sort_by:
        try:
            idx = [k for k, _ in cols].index(sort_by)
            rows.sort(key=lambda r: r[idx], reverse=sort_reverse)
        except ValueError:
            pass  # unknown key; skip sorting

    table = Table(
        title=title,
        caption=caption,
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_lines=False,
        expand=True,
    )

    # Add columns
    for _key, header in cols:
        table.add_column(header, overflow="fold", no_wrap=False)

    # Add rows with optional status styling
    for row in rows:
        styled_cells: List[str] = []
        for (key, _hdr), cell in zip(cols, row):
            if style_status:
                lk = key.lower()
                if lk in ("status", "ok", "failed"):
                    lc = cell.strip().lower()
                    if lc in ("ok", "success", "passed", "true", "yes"):
                        cell = "[bold green]OK[/]"
                    elif lc in ("fail", "failed", "error", "false", "no"):
                        cell = "[bold red]FAIL[/]"
            styled_cells.append(cell)
        table.add_row(*styled_cells)

    _console.print(table)


def print_device_table(entries: List[Dict[str, Any]]) -> None:
    """
    Convenience wrapper for common network columns.
    Expects dicts like:
      {"device": "...", "ip": "...", "platform": "...", "model": "...", "status": "OK/FAIL", "info": "..."}
    Extra keys are ignored unless you add them to the columns list below.
    """
    columns = [
        ("device", "Device"),
        ("ip", "IP"),
        ("platform", "Platform"),
        ("model", "Model"),
        ("status", "Status"),
        ("info", "Info"),
    ]
    print_table(entries, columns=columns, title="Device Summary", sort_by="device")