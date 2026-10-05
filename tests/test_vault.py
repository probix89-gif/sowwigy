from pathlib import Path

from swiggy_hunter.auth.vault import SessionVault
from swiggy_hunter.state.schemas import SessionInfo


def test_roundtrip(tmp_path: Path):
    v = SessionVault(data_dir=tmp_path)
    s = SessionInfo(name="primary", phone="9876543210",
                    cookies={"a": "1"}, fingerprint_id="chrome124-win")
    v.save(s)
    loaded = v.load("primary")
    assert loaded is not None
    assert loaded.phone == "9876543210"
    assert loaded.cookies["a"] == "1"


def test_list_and_delete(tmp_path: Path):
    v = SessionVault(data_dir=tmp_path)
    v.save(SessionInfo(name="x", cookies={"a": "1"}))
    assert "x" in v.list_names()
    assert v.delete("x")
    assert "x" not in v.list_names()


def test_persistence_across_instances(tmp_path: Path):
    v = SessionVault(data_dir=tmp_path)
    v.save(SessionInfo(name="p", phone="1", cookies={"a": "1"}))
    # new instance, same dir
    v2 = SessionVault(data_dir=tmp_path)
    assert v2.load("p") is not None
