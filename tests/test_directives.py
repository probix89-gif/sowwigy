from pathlib import Path

from swiggy_hunter.directives import DirectiveQueue


def test_push_and_consume(tmp_path: Path):
    q = DirectiveQueue(path=tmp_path / "d.jsonl")
    d = q.push("hello", kind="chat")
    pending = q.pending()
    assert len(pending) == 1
    assert pending[0].text == "hello"

    q.mark_consumed([d.id], response="got it")
    assert q.pending() == []

    recent = q.recent(limit=1)
    assert recent[0].response == "got it"
