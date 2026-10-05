import asyncio
from pathlib import Path
import sys

import pytest

from core.tool_fabric import (
    ToolExecutor,
    ToolFabricError,
    ToolIntegrityError,
    ToolNotRegisteredError,
    ToolPolicyError,
    ToolRequest,
    ToolSpec,
    ToolRegistry,
    ToolTimeoutError,
    sha256_file,
)


def python_spec(tmp_path: Path, **kwargs) -> ToolSpec:
    return ToolSpec(
        name="python",
        executable=Path(sys.executable).resolve(),
        version=sys.version.split()[0],
        action_class="REPOSITORY_ANALYSIS",
        cwd=tmp_path,
        **kwargs,
    )


def test_registry_requires_unique_allowlisted_tools(tmp_path):
    registry = ToolRegistry()
    spec = python_spec(tmp_path)
    registry.register(spec)
    assert registry.names() == ("python",)
    with pytest.raises(ToolPolicyError):
        registry.register(spec)
    with pytest.raises(ToolNotRegisteredError):
        registry.get("missing")


def test_tool_spec_rejects_relative_or_invalid_digest(tmp_path):
    with pytest.raises(ValueError):
        ToolSpec(
            name="x",
            executable=Path("python"),
            version="1",
            action_class="PASSIVE_RECON",
        )
    with pytest.raises(ValueError):
        ToolSpec(
            name="x",
            executable=Path(sys.executable).resolve(),
            version="1",
            action_class="PASSIVE_RECON",
            expected_sha256="not-a-digest",
        )


def test_request_rejects_nul_bytes():
    with pytest.raises(ValueError):
        ToolRequest(tool="python", args=("bad\x00arg",))


@pytest.mark.asyncio
async def test_executor_runs_without_shell_and_captures_bounded_output(tmp_path):
    registry = ToolRegistry()
    registry.register(python_spec(tmp_path, max_output_bytes=32))
    executor = ToolExecutor(registry)

    result = await executor.run(
        ToolRequest(
            tool="python",
            args=("-c", "print('safe')"),
        )
    )
    assert result.succeeded
    assert result.exit_code == 0
    assert result.stdout.strip() == "safe"
    assert result.action_class == "REPOSITORY_ANALYSIS"
    assert len(result.executable_sha256) == 64


@pytest.mark.asyncio
async def test_executor_does_not_interpret_shell_metacharacters(tmp_path):
    registry = ToolRegistry()
    registry.register(python_spec(tmp_path))
    executor = ToolExecutor(registry)
    result = await executor.run(
        ToolRequest(tool="python", args=("-c", "import sys; print(sys.argv[1])", "a;echo pwned"))
    )
    assert result.succeeded
    assert "a;echo pwned" in result.stdout


@pytest.mark.asyncio
async def test_executor_enforces_environment_allowlist(tmp_path):
    registry = ToolRegistry()
    registry.register(python_spec(tmp_path, environment_keys=("SAFE_TOKEN",)))
    executor = ToolExecutor(registry)
    with pytest.raises(ToolPolicyError):
        await executor.run(
            ToolRequest(tool="python", args=("-c", "pass"), environment={"SECRET": "x"})
        )


@pytest.mark.asyncio
async def test_executor_enforces_digest(tmp_path):
    registry = ToolRegistry()
    registry.register(
        python_spec(tmp_path, expected_sha256="0" * 64)
    )
    executor = ToolExecutor(registry)
    with pytest.raises(ToolIntegrityError):
        await executor.run(ToolRequest(tool="python", args=("-c", "pass")))


@pytest.mark.asyncio
async def test_executor_enforces_timeout_and_kills_process(tmp_path):
    registry = ToolRegistry()
    registry.register(python_spec(tmp_path, timeout_seconds=0.05))
    executor = ToolExecutor(registry)
    with pytest.raises(ToolTimeoutError):
        await executor.run(
            ToolRequest(tool="python", args=("-c", "import time; time.sleep(2)"))
        )


@pytest.mark.asyncio
async def test_executor_enforces_argument_and_cwd_policy(tmp_path):
    registry = ToolRegistry()
    registry.register(python_spec(tmp_path, max_argument_bytes=20))
    executor = ToolExecutor(registry)
    with pytest.raises(ToolPolicyError):
        await executor.run(ToolRequest(tool="python", args=("-c", "print('this is too long')")))

    with pytest.raises(ToolPolicyError):
        await executor.run(
            ToolRequest(
                tool="python",
                args=("-c", "pass"),
                cwd=tmp_path / "missing",
            )
        )


def test_sha256_file(tmp_path):
    path = tmp_path / "sample"
    path.write_bytes(b"bugflow")
    assert len(sha256_file(path)) == 64


@pytest.mark.asyncio
async def test_executor_allows_declared_environment_key(tmp_path):
    registry = ToolRegistry()
    registry.register(python_spec(tmp_path, environment_keys=("SAFE_TOKEN",)))
    executor = ToolExecutor(registry)
    result = await executor.run(
        ToolRequest(
            tool="python",
            args=("-c", "import os; print(os.environ['SAFE_TOKEN'])"),
            environment={"SAFE_TOKEN": "present"},
        )
    )
    assert result.succeeded
    assert result.stdout.strip() == "present"


@pytest.mark.asyncio
async def test_executor_reports_nonzero_exit_and_truncates_output(tmp_path):
    registry = ToolRegistry()
    registry.register(python_spec(tmp_path, max_output_bytes=8))
    executor = ToolExecutor(registry)
    result = await executor.run(
        ToolRequest(tool="python", args=("-c", "import sys; print('0123456789abcdef'); sys.exit(3)"))
    )
    assert not result.succeeded
    assert result.exit_code == 3
    assert result.output_truncated is True
    assert len(result.stdout.encode("utf-8")) <= 8


@pytest.mark.asyncio
async def test_executor_respects_minimum_start_interval(tmp_path):
    registry = ToolRegistry()
    registry.register(python_spec(tmp_path, min_interval_seconds=0.01))
    executor = ToolExecutor(registry)
    first = await executor.run(ToolRequest(tool="python", args=("-c", "print('1')")))
    second = await executor.run(ToolRequest(tool="python", args=("-c", "print('2')")))
    assert first.succeeded and second.succeeded
    assert second.started_at >= first.started_at
