from swiggy_hunter.state.schemas import AgentName, Finding, Task


async def test_finding_roundtrip(blackboard):
    f = Finding(title="t", category="recon", description="d",
                discovered_by=AgentName.recon)
    await blackboard.upsert_finding(f)
    got = await blackboard.get_finding(f.id)
    assert got is not None and got.title == "t"


async def test_task_flow(blackboard):
    t = Task(title="t", assignee=AgentName.recon, priority=3)
    await blackboard.add_task(t)
    nxt = await blackboard.next_task_for("recon")
    assert nxt is not None and nxt.id == t.id


async def test_narrative(blackboard):
    await blackboard.set_narrative(mission="find bugs")
    text = blackboard.path.read_text(encoding="utf-8")
    assert "find bugs" in text
