"""GET /api/tasks?task_type=... lists only those task types: the YARA page
reads its recent file and memory scans from it, so a scan still shows after
the analyst leaves the page and comes back."""


async def test_task_type_filter_takes_several_types(evidence_api):
    from app.api.routes.tasks import list_tasks
    from app.models.models import AgentTask

    blue, red = evidence_api.agents["blue"], evidence_api.agents["red"]
    async with evidence_api.sessions() as db:
        db.add_all([
            AgentTask(agent_id=blue, task_type="yara_scan", params={"path": "/var/www"}, status="running"),
            AgentTask(agent_id=blue, task_type="memory_scan", params={"pid": 0}, status="done"),
            AgentTask(agent_id=blue, task_type="block_ip", params={"ip": "45.129.56.138"}),
        ])
        await db.commit()

    async with evidence_api.sessions() as db:
        scans = await list_tasks(db=db, group_filter=None, _=None, task_type="yara_scan, memory_scan")
        only_yara = await list_tasks(db=db, group_filter=None, _=None, task_type="yara_scan")
        everything = await list_tasks(db=db, group_filter=None, _=None)
        other_group = await list_tasks(db=db, group_filter="red", _=None, task_type="yara_scan,memory_scan")

    assert sorted(t.task_type for t in scans) == ["memory_scan", "yara_scan"]
    assert [t.task_type for t in only_yara] == ["yara_scan"]
    assert len(everything) == 3
    assert other_group == [] and red not in {t.agent_id for t in scans}
