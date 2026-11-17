"""On-disk Trivy layer caches, one per parallel scan, kept between runs so a rescan skips layers it has analysed.

Trivy's ``fs`` cache backend is a BoltDB file (``<cache-dir>/fanal/fanal.db``) that one Trivy process locks for its
whole scan, so parallel scans cannot share one. Each scan instead takes one of ``SLOTS`` slots, ``<root>/slot-K``
(created when first used), for as long as its image takes: a directory with its own layer cache and links to the
shared vulnerability and Java DBs, which Trivy looks for in the same ``--cache-dir`` and
:class:`kubedelos.trivy.cache.TrivyCache` keeps up to date. A slot is held with a ``flock`` on its lock file, so a
second ``kubedelos ui`` process never uses a slot this one is scanning with; when no slot is free the scan keeps its
layer cache in memory, as before.

A repository first tries the slot its name hashes to, so its next scan (or a new tag sharing its layers) finds them.
The slot count is fixed, so that slot stays the same whatever the parallelism, and with fewer parallel scans than
slots a repository rarely finds its slot busy and goes to another. The cache holds analysis results, not image blobs
(about 1-4 MB an image), and a slot that has grown past ``max_bytes`` is emptied before it is next used.
"""

import contextlib
import fcntl
import os
import shutil
import threading
import zlib
from collections.abc import Iterator
from pathlib import Path

SLOTS = 32  # one for each parallel scan Settings allows
MAX_SLOT_BYTES = 128 * 1024 * 1024  # about 50 images a slot, at most 4 GB in all
_LOCK_FILE = ".kubedelos.lock"
_LAYER_DIR = "fanal"  # where Trivy's fs backend keeps its layer cache inside --cache-dir
_SHARED = ("db", "java-db")  # linked to the shared DB dir


def _size(path: Path) -> int:
    total = 0
    for parent, _, files in os.walk(path):
        for name in files:
            with contextlib.suppress(OSError):
                total += os.lstat(os.path.join(parent, name)).st_size
    return total


class LayerSlots:
    """``count`` layer cache slots under ``root``, each linking ``db_dir``'s DBs; :meth:`take` lends one out."""

    def __init__(self, db_dir: Path, root: Path, count: int = SLOTS, *, max_bytes: int = MAX_SLOT_BYTES) -> None:
        self.db_dir = db_dir
        self.root = root
        self.count = count
        self.max_bytes = max_bytes
        self._held: set[int] = set()  # slots this process lends out now
        self._guard = threading.Lock()

    @contextlib.contextmanager
    def take(self, repo: str = "") -> Iterator[Path | None]:
        """A free slot's directory for the length of the ``with`` block, ``repo``'s own slot when it is free, or
        ``None`` when every slot is busy."""
        taken = self._lock_free_slot(zlib.crc32(repo.encode()) % self.count)  # stable across runs and processes
        if taken is None:
            yield None
            return
        index, fd = taken
        try:
            yield self._prepare(self.root / f"slot-{index}")
        finally:
            os.close(fd)  # releases the flock
            with self._guard:
                self._held.discard(index)

    def _lock_free_slot(self, first: int) -> tuple[int, int] | None:
        with self._guard:
            for index in (*range(first, self.count), *range(first)):
                if index in self._held:
                    continue
                slot = self.root / f"slot-{index}"
                try:
                    slot.mkdir(parents=True, exist_ok=True)
                    fd = os.open(slot / _LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
                except OSError:
                    continue
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:  # another kubedelos process scans with it
                    os.close(fd)
                    continue
                self._held.add(index)
                return index, fd
        return None

    def _prepare(self, slot: Path) -> Path:
        layers = slot / _LAYER_DIR
        if layers.exists() and _size(layers) > self.max_bytes:
            shutil.rmtree(layers, ignore_errors=True)
        for name in _SHARED:
            link, target = slot / name, (self.db_dir / name).absolute()  # a link resolves from its own dir
            if link.is_symlink() and link.readlink() == target:
                continue
            if link.is_dir() and not link.is_symlink():
                shutil.rmtree(link)
            elif link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(target, target_is_directory=True)
        return slot
