"""Governed local tool execution fabric.

Phase 1 centralizes process execution so individual BugFlow modules do not
invent their own subprocess policy. The fabric is deliberately authority-light:
target scope, approval, tenant policy, and sandbox authority remain upstream.
It enforces executable identity, argv-only execution, bounded resources, and
structured execution results.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from hashlib import sha256
import os
from pathlib import Path
import signal
import time
from typing import Mapping, Sequence


class ToolFabricError(RuntimeError):
    """Base error for governed tool execution."""


class ToolNotRegisteredError(ToolFabricError):
    """Raised when a caller requests an unregistered tool."""


class ToolPolicyError(ToolFabricError):
    """Raised when a tool violates its execution policy."""


class ToolIntegrityError(ToolFabricError):
    """Raised when the executable identity does not match policy."""


class ToolTimeoutError(ToolFabricError):
    """Raised when a tool exceeds its configured execution budget."""


@dataclass(frozen=True)
class ToolSpec:
    """Immutable allowlisted description of an executable."""

    name: str
    executable: Path
    version: str
    action_class: str
    timeout_seconds: float = 300.0
    max_output_bytes: int = 4_000_000
    max_argument_bytes: int = 64_000
    expected_sha256: str | None = None
    max_concurrency: int = 1
    min_interval_seconds: float = 0.0
    environment_keys: tuple[str, ...] = ()
    cwd: Path | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("tool name must not be empty")
        if not self.version.strip():
            raise ValueError("tool version must not be empty")
        if not self.action_class.strip():
            raise ValueError("action_class must not be empty")
        if not self.executable.is_absolute():
            raise ValueError("tool executable must be an absolute path")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        if self.max_argument_bytes <= 0:
            raise ValueError("max_argument_bytes must be positive")
        if self.max_concurrency <= 0:
            raise ValueError("max_concurrency must be positive")
        if self.min_interval_seconds < 0:
            raise ValueError("min_interval_seconds cannot be negative")
        if self.expected_sha256 is not None:
            digest = self.expected_sha256.lower()
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("expected_sha256 must be a 64-character hex digest")


@dataclass(frozen=True)
class ToolRequest:
    """A fully materialized argv request.

    User-controlled values are arguments, never shell source. The executable
    is always taken from the registered ToolSpec.
    """

    tool: str
    args: tuple[str, ...] = ()
    environment: Mapping[str, str] = field(default_factory=dict)
    cwd: Path | None = None

    def __post_init__(self) -> None:
        if not self.tool.strip():
            raise ValueError("tool must not be empty")
        if any("\x00" in arg for arg in self.args):
            raise ValueError("NUL bytes are not valid command arguments")
        if any("\x00" in key or "\x00" in value for key, value in self.environment.items()):
            raise ValueError("NUL bytes are not valid environment values")


@dataclass(frozen=True)
class ToolResult:
    """Structured, bounded execution result."""

    tool: str
    argv: tuple[str, ...]
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool
    output_truncated: bool
    executable_sha256: str
    action_class: str
    started_at: float

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Hash an executable without loading the whole file into memory."""
    digest = sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


class ToolRegistry:
    """Explicit allowlist for executable identities."""

    def __init__(self) -> None:
        self._specs: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._specs:
            raise ToolPolicyError(f"tool already registered: {spec.name}")
        self._specs[spec.name] = spec

    def get(self, name: str) -> ToolSpec:
        try:
            return self._specs[name]
        except KeyError as exc:
            raise ToolNotRegisteredError(f"tool is not registered: {name}") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._specs))


class ToolExecutor:
    """Bounded subprocess executor with no shell interpretation."""

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry
        self._semaphores: dict[str, asyncio.Semaphore] = {}
        self._last_start: dict[str, float] = {}

    async def run(self, request: ToolRequest) -> ToolResult:
        spec = self.registry.get(request.tool)
        executable = spec.executable.resolve()

        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ToolPolicyError(f"configured executable is not executable: {executable}")

        digest = sha256_file(executable)
        if spec.expected_sha256 and digest != spec.expected_sha256.lower():
            raise ToolIntegrityError(
                f"executable digest mismatch for {spec.name}: expected "
                f"{spec.expected_sha256.lower()}, got {digest}"
            )

        argv = (str(executable), *request.args)
        argument_bytes = sum(len(arg.encode("utf-8")) + 1 for arg in argv)
        if argument_bytes > spec.max_argument_bytes:
            raise ToolPolicyError(
                f"argument budget exceeded for {spec.name}: "
                f"{argument_bytes}>{spec.max_argument_bytes}"
            )

        env = os.environ.copy()
        for key in spec.environment_keys:
            if key in request.environment:
                env[key] = request.environment[key]
        unexpected = set(request.environment) - set(spec.environment_keys)
        if unexpected:
            raise ToolPolicyError(
                f"environment keys not allowlisted for {spec.name}: "
                + ", ".join(sorted(unexpected))
            )

        cwd = request.cwd or spec.cwd
        if cwd is not None:
            cwd = cwd.resolve()
            if not cwd.is_dir():
                raise ToolPolicyError(f"execution cwd does not exist: {cwd}")

        semaphore = self._semaphores.setdefault(
            spec.name, asyncio.Semaphore(spec.max_concurrency)
        )

        async with semaphore:
            await self._respect_interval(spec)
            started_at = time.time()
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
                env=env,
                start_new_session=(os.name == "posix"),
            )
            self._last_start[spec.name] = started_at

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=spec.timeout_seconds,
                )
            except asyncio.TimeoutError as exc:
                await self._terminate(proc)
                await proc.communicate()
                raise ToolTimeoutError(
                    f"{spec.name} exceeded {spec.timeout_seconds}s timeout"
                ) from exc

        output_truncated = len(stdout) > spec.max_output_bytes or len(stderr) > spec.max_output_bytes
        stdout = stdout[: spec.max_output_bytes]
        stderr = stderr[: spec.max_output_bytes]
        return ToolResult(
            tool=spec.name,
            argv=argv,
            exit_code=proc.returncode,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            duration_seconds=max(0.0, time.time() - started_at),
            timed_out=False,
            output_truncated=output_truncated,
            executable_sha256=digest,
            action_class=spec.action_class,
            started_at=started_at,
        )

    async def _respect_interval(self, spec: ToolSpec) -> None:
        if spec.min_interval_seconds <= 0:
            return
        last = self._last_start.get(spec.name)
        if last is None:
            return
        delay = spec.min_interval_seconds - (time.time() - last)
        if delay > 0:
            await asyncio.sleep(delay)

    @staticmethod
    async def _terminate(proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is not None:
            return
        if os.name == "posix":
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                return
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except asyncio.TimeoutError:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        else:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except asyncio.TimeoutError:
                proc.kill()
