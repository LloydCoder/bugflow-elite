import pytest

from core.research_planner import (
    ResearchTask,
    enumerate_attack_paths,
    propose_followup_tasks,
    topological_plan,
)


def test_followup_planner_is_deterministic_and_bounded():
    tasks = propose_followup_tasks(
        target="https://example.com",
        changes=[{"url": "https://example.com/app.js"}],
        findings=[{"vuln_type": "idor"}],
    )
    assert [task.priority for task in tasks] == [0.85, 0.80]
    assert all(0.0 <= task.priority <= 1.0 for task in tasks)


def test_topological_plan_respects_prerequisites_and_rejects_cycles():
    a = ResearchTask("a", "WEB_REQUEST", "example.com", "base", 0.5)
    b = ResearchTask("b", "PARAM_DISCOVERY", "example.com", "follow-up", 0.8, ("a",))
    assert [task.task_id for task in topological_plan((b, a))] == ["a", "b"]

    c = ResearchTask("c", "WEB_REQUEST", "example.com", "cycle", 0.5, ("d",))
    d = ResearchTask("d", "WEB_REQUEST", "example.com", "cycle", 0.5, ("c",))
    with pytest.raises(ValueError):
        topological_plan((c, d))


def test_attack_paths_are_bounded_and_cycle_safe():
    edges = {
        "internet": ("cdn", "admin"),
        "cdn": ("api",),
        "api": ("db",),
        "admin": ("db",),
    }
    paths = enumerate_attack_paths(edges, start="internet", goals={"db"}, max_hops=3)
    assert ("internet", "admin", "db") in paths
    assert ("internet", "cdn", "api", "db") in paths


def test_invalid_task_and_path_limits():
    with pytest.raises(ValueError):
        ResearchTask("", "WEB_REQUEST", "example.com", "x", 0.5)
    with pytest.raises(ValueError):
        ResearchTask("x", "WEB_REQUEST", "example.com", "x", 1.5)
    with pytest.raises(ValueError):
        enumerate_attack_paths({}, start="x", goals={"y"}, max_hops=0)
