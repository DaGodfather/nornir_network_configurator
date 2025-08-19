# progress_manager.py
from typing import Dict, Optional, Any
from contextlib import contextmanager
from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

class ProgressManager:
    """
    Thin wrapper around rich.Progress tailored for network tasks.
    - Reusable across files
    - Simple lifecycle: start()/stop() or 'with progress:' context
    - Host-aware: show the device name in its own column
    - Keeps a task registry so you can advance by host or task_id
    """

    def __init__(self) -> None:
        self._progress = Progress(
            TextColumn("[bold blue]{task.fields[host]}", justify="right"),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>5.1f}%",
            TimeElapsedColumn(),
            TimeRemainingColumn(),
        )
        # Maps: host -> task_id
        self._host_to_task: Dict[str, "TaskID"] = {}
        self._running = False

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Begin rendering the progress UI (call once)."""
        if not self._running:
            self._progress.start()
            self._running = True

    def stop(self) -> None:
        """Stop rendering the progress UI (safe to call multiple times)."""
        if self._running:
            self._progress.stop()
            self._running = False

    def __enter__(self) -> "ProgressManager":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    @contextmanager
    def live(self):
        """
        Optional: use as a context manager when you want a local scope:

            with pm.live():
                ...
        """
        self.start()
        try:
            yield self
        finally:
            self.stop()

    # --- task API ----------------------------------------------------------

    def add_task(
        self,
        host: str,
        total: Optional[float] = None,
        description: str = "Working...",
        **fields: Any
    ) -> "TaskID":
        """
        Create or return a task for a host. If the host already has a task,
        we return the existing task_id.
        """
        if host in self._host_to_task:
            return self._host_to_task[host]

        task_id = self._progress.add_task(
            description,
            total=total,
            host=host,
            **fields  # extra fields available as task.fields[<name>]
        )
        self._host_to_task[host] = task_id
        return task_id

    def update(
        self,
        host: Optional[str] = None,
        task_id: Optional["TaskID"] = None,
        advance: Optional[float] = None,
        completed: Optional[float] = None,
        total: Optional[float] = None,
        description: Optional[str] = None,
        **fields: Any
    ) -> None:
        """
        Update a task by host or task_id.
        """
        tid = self._resolve_task_id(host, task_id)
        kwargs: Dict[str, Any] = {}
        if advance is not None:
            kwargs["advance"] = advance
        if completed is not None:
            kwargs["completed"] = completed
        if total is not None:
            kwargs["total"] = total
        if description is not None:
            kwargs["description"] = description
        if fields:
            kwargs["fields"] = fields
        if tid is not None:
            self._progress.update(tid, **kwargs)

    def advance(self, host: Optional[str] = None, task_id: Optional["TaskID"] = None, step: float = 1.0) -> None:
        """
        Convenience: advance a task by a step.
        """
        self.update(host=host, task_id=task_id, advance=step)

    def complete(self, host: Optional[str] = None, task_id: Optional["TaskID"] = None) -> None:
        """
        Mark a task as complete (completed == total).
        """
        tid = self._resolve_task_id(host, task_id)
        if tid is not None:
            task = self._progress.tasks[tid]
            if task.total is not None:
                self._progress.update(tid, completed=task.total)

    def get_task_id(self, host: str) -> Optional["TaskID"]:
        return self._host_to_task.get(host)

    def _resolve_task_id(self, host: Optional[str], task_id: Optional["TaskID"]) -> Optional["TaskID"]:
        if task_id is not None:
            return task_id
        if host is not None:
            return self._host_to_task.get(host)
        return None

    # --- escape hatch: access the raw Progress if needed -------------------

    @property
    def progress(self) -> Progress:
        return self._progress


# --- singleton-style accessor if you prefer importing one instance ---------

# Create a single instance that can be imported app-wide.
_progress_singleton: Optional[ProgressManager] = None

def get_progress_manager() -> ProgressManager:
    global _progress_singleton
    if _progress_singleton is None:
        _progress_singleton = ProgressManager()
    return _progress_singleton
