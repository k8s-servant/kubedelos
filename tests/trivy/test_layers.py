import fcntl
import os
import threading
import time
from pathlib import Path

from kubedelos.config import Settings
from kubedelos.trivy.layers import SLOTS, LayerSlots


def _slots(tmp_path, count=2, **kw):
    db_dir = tmp_path / "trivy-cache"
    for sub in ("db", "java-db"):
        (db_dir / sub).mkdir(parents=True, exist_ok=True)
    return LayerSlots(db_dir, tmp_path / "trivy-layers", count, **kw)


def test_a_slot_links_the_shared_dbs(tmp_path):
    with _slots(tmp_path).take() as slot:
        assert slot == tmp_path / "trivy-layers" / "slot-0"
        for sub in ("db", "java-db"):
            assert (slot / sub).is_symlink() and (slot / sub).resolve() == (tmp_path / "trivy-cache" / sub).resolve()


def test_slots_taken_at_once_differ_and_run_out(tmp_path):
    slots = _slots(tmp_path, count=2)
    with slots.take() as first, slots.take() as second, slots.take() as third:
        assert {first.name, second.name} == {"slot-0", "slot-1"}
        assert third is None  # every slot is busy: this scan keeps its layer cache in memory
    with slots.take() as again:
        assert again is not None


def test_a_slot_another_process_holds_is_skipped(tmp_path):
    slots = _slots(tmp_path, count=2)
    (tmp_path / "trivy-layers" / "slot-0").mkdir(parents=True)
    fd = os.open(tmp_path / "trivy-layers" / "slot-0" / ".kubedelos.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # another open file: flock treats it as another holder
        with slots.take() as slot:
            assert slot.name == "slot-1"
    finally:
        os.close(fd)


def test_the_layer_cache_stays_between_takes(tmp_path):
    slots = _slots(tmp_path, count=1)
    with slots.take() as slot:
        (slot / "fanal").mkdir()
        (slot / "fanal" / "fanal.db").write_bytes(b"x" * 100)
    with slots.take() as slot:
        assert (slot / "fanal" / "fanal.db").read_bytes() == b"x" * 100


def test_a_slot_over_the_cap_is_emptied_before_use(tmp_path):
    slots = _slots(tmp_path, count=1, max_bytes=1000)
    with slots.take() as slot:
        (slot / "fanal").mkdir()
        (slot / "fanal" / "fanal.db").write_bytes(b"x" * 1001)
    with slots.take() as slot:
        assert not (slot / "fanal").exists()
        assert (slot / "db").is_symlink()  # the links stay


def test_a_slot_at_the_cap_is_kept(tmp_path):
    slots = _slots(tmp_path, count=1, max_bytes=1000)
    with slots.take() as slot:
        (slot / "fanal").mkdir()
        (slot / "fanal" / "fanal.db").write_bytes(b"x" * 1000)
    with slots.take() as slot:
        assert (slot / "fanal" / "fanal.db").exists()


def test_a_wrong_link_or_a_stray_entry_is_replaced(tmp_path):
    slot_dir = tmp_path / "trivy-layers" / "slot-0"
    slot_dir.mkdir(parents=True)
    (slot_dir / "db").symlink_to(tmp_path / "elsewhere")
    (slot_dir / "java-db").mkdir()  # a real directory where the link belongs
    (slot_dir / "java-db" / "trivy-java.db").write_text("old")
    with _slots(tmp_path, count=1).take() as slot:
        for sub in ("db", "java-db"):
            assert (slot / sub).resolve() == (tmp_path / "trivy-cache" / sub).resolve()


def test_threads_never_share_a_slot(tmp_path):
    slots = _slots(tmp_path, count=3)
    held: set[str] = set()
    guard = threading.Lock()
    clashes: list[str] = []

    def worker():
        for _ in range(20):
            with slots.take() as slot:
                if slot is None:
                    continue
                with guard:
                    if slot.name in held:
                        clashes.append(slot.name)
                    held.add(slot.name)
                time.sleep(0.001)
                with guard:
                    held.discard(slot.name)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert clashes == []


def test_links_are_absolute_for_a_relative_cache_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "rel" / "trivy-cache" / "db").mkdir(parents=True)
    slots = LayerSlots(Path("rel/trivy-cache"), Path("rel/trivy-layers"), 1)
    with slots.take() as slot:
        assert (slot / "db").readlink().is_absolute() and (slot / "db").resolve() == (
            tmp_path / "rel/trivy-cache/db"
        ).resolve()


def test_an_image_goes_back_to_its_own_slot(tmp_path):
    slots = _slots(tmp_path, count=4)
    with slots.take("reg.example.com/app") as first:
        pass
    for _ in range(3):
        with slots.take("reg.example.com/app") as again:
            assert again == first  # its layers are there
    names = set()
    for i in range(40):
        with slots.take(f"reg.example.com/app-{i}") as slot:
            names.add(slot.name)
    assert len(names) == 4  # repositories spread over every slot


def test_a_busy_own_slot_falls_back_to_another(tmp_path):
    slots = _slots(tmp_path, count=2)
    with slots.take("reg.example.com/app") as own, slots.take("reg.example.com/app") as other:
        assert other is not None and other != own


def test_there_is_a_slot_for_every_parallel_scan_allowed():
    (bound,) = [m.le for m in Settings.model_fields["parallelism"].metadata if hasattr(m, "le")]
    assert bound == SLOTS
