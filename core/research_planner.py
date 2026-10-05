"""Bounded autonomous research planning and attack-path reasoning.

Planning produces proposed tasks; it does not execute them. Execution remains
governed by scope, capability, approval, and the Tool Fabric.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Sequence


class PlannerState(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    RUNNING = "running"
    COMPLETED = "completed"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class ResearchTask:
    task_id: str
    action_class: str
    target: str
    rationale: str
    priority: float
    prerequisites: tuple[str, ...] = ()
    state: PlannerState = PlannerState.PROPOSED

    def __post_init__(self) -> None:
        if not self.task_id.strip() or not self.action_class.strip() or not self.target.strip():
            raise ValueError("research task identity is required")
        if not 0.0 <= self.priority <= 1.0:
            raise ValueError("task priority must be between 0 and 1")


def propose_followup_tasks(
    *,
    target: str,
    changes: Sequence[Mapping[str, object]],
    findings: Sequence[Mapping[str, object]],
) -> tuple[ResearchTask, ...]:
    tasks: list[ResearchTask] = []
    if changes:
        tasks.append(
            ResearchTask(
                task_id=f"change-recheck:{target}",
                action_class="WEB_REQUEST",
                target=target,
                rationale="Re-analyze changed attack-surface content",
                priority=0.85,
            )
        )
    if any(str(item.get("vuln_type", "")).lower() in {"api", "idor", "auth"} for item in findings):
        tasks.append(
            ResearchTask(
                task_id=f"api-followup:{target}",
                action_class="PARAM_DISCOVERY",
                target=target,
                rationale="Investigate related API parameters and authorization boundaries",
                priority=0.80,
            )
        )
    return tuple(sorted(tasks, key=lambda task: (-task.priority, task.task_id)))


def topological_plan(tasks: Sequence[ResearchTask]) -> tuple[ResearchTask, ...]:
    """Return a deterministic prerequisite-respecting order; cycles fail closed."""
    by_id = {task.task_id: task for task in tasks}
    visiting: set[str] = set()
    visited: set[str] = set()
    ordered: list[ResearchTask] = []

    def visit(task_id: str) -> None:
        if task_id in visiting:
            raise ValueError("research task dependency cycle")
        if task_id in visited:
            return
        task = by_id.get(task_id)
        if task is None:
            raise ValueError(f"unknown prerequisite: {task_id}")
        visiting.add(task_id)
        for prerequisite in task.prerequisites:
            visit(prerequisite)
        visiting.remove(task_id)
        visited.add(task_id)
        ordered.append(task)

    for task in sorted(tasks, key=lambda item: item.task_id):
        visit(task.task_id)
    return tuple(ordered)


def enumerate_attack_paths(
    edges: Mapping[str, Sequence[str]],
    *,
    start: str,
    goals: set[str],
    max_hops: int = 5,
) -> tuple[tuple[str, ...], ...]:
    if max_hops <= 0:
        raise ValueError("max_hops must be positive")
    paths: list[tuple[str, ...]] = []

    def walk(node: str, path: tuple[str, ...]) -> None:
        if len(path) - 1 > max_hops:
            return
        if node in goals:
            paths.append(path)
            return
        for neighbor in sorted(set(edges.get(node, ()))):
            if neighbor in path:
                continue
            walk(neighbor, path + (neighbor,))

    walk(start, (start,))
    return tuple(paths)
