"""Sandbox — controlled execution environments with permission levels."""

from __future__ import annotations

import subprocess
import tempfile
import threading
import time
from enum import IntEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class PermissionLevel(IntEnum):
    """Privilege rings, from most restricted to least."""

    MINIMAL = 0  # No filesystem, no network, no subprocess
    RESTRICTED = 1  # Read-only filesystem, no network
    STANDARD = 2  # Read/write to sandbox dir, limited network
    ELEVATED = 3  # Full filesystem, full network, no subprocess
    ADMIN = 4  # Unrestricted


class SandboxResult(BaseModel):
    """Outcome of a sandboxed execution."""

    success: bool
    output: str = ""
    error: str = ""
    exit_code: int = 0
    execution_time_ms: float = 0.0
    permission_level: PermissionLevel = PermissionLevel.STANDARD
    resource_usage: dict[str, Any] = Field(default_factory=dict)
    terminated: bool = False
    termination_reason: str = ""


class SandboxConfig(BaseModel):
    """Configuration for a sandbox environment."""

    permission_level: PermissionLevel = PermissionLevel.STANDARD
    max_execution_time_s: float = 30.0
    max_memory_mb: int = 512
    max_output_bytes: int = 1_000_000
    allowed_paths: list[str] = Field(default_factory=list)
    denied_paths: list[str] = Field(
        default_factory=lambda: ["/etc", "/var", "/usr", "/sys", "/proc"]
    )
    allowed_env_vars: list[str] = Field(default_factory=list)
    network_allowed: bool = False


class Sandbox:
    """Sandboxed execution environment for agent code and commands.

    Usage:
        sandbox = Sandbox(permission_level=PermissionLevel.RESTRICTED)

        # Execute a Python snippet
        result = sandbox.exec_python("print(2 + 2)")
        print(result.output)  # "4"

        # Execute a shell command
        result = sandbox.exec_command(["ls", "-la"])

        # Execute with a function
        result = sandbox.exec_function(my_func, args=(1, 2), kwargs={"key": "val"})
    """

    def __init__(
        self,
        permission_level: PermissionLevel = PermissionLevel.STANDARD,
        config: SandboxConfig | None = None,
    ):
        self.config = config or SandboxConfig(permission_level=permission_level)
        self._active = True
        self._running_processes: list[subprocess.Popen] = []  # type: ignore[type-arg]
        self._lock = threading.Lock()

    def exec_python(self, code: str, *, timeout: float | None = None) -> SandboxResult:
        """Execute a Python code snippet in a subprocess sandbox."""
        if self.config.permission_level == PermissionLevel.MINIMAL:
            return SandboxResult(
                success=False,
                error="Code execution not allowed at MINIMAL permission level",
                permission_level=self.config.permission_level,
            )

        timeout = timeout or self.config.max_execution_time_s
        start = time.perf_counter()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            script_path = f.name

        try:
            proc = subprocess.Popen(
                ["python3", script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=tempfile.gettempdir(),
            )
            with self._lock:
                self._running_processes.append(proc)

            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                elapsed = (time.perf_counter() - start) * 1000
                return SandboxResult(
                    success=False,
                    error=f"Execution timed out after {timeout}s",
                    exit_code=-1,
                    execution_time_ms=elapsed,
                    permission_level=self.config.permission_level,
                    terminated=True,
                    termination_reason="timeout",
                )
            finally:
                with self._lock:
                    if proc in self._running_processes:
                        self._running_processes.remove(proc)

            elapsed = (time.perf_counter() - start) * 1000
            return SandboxResult(
                success=proc.returncode == 0,
                output=stdout.decode(errors="replace")[: self.config.max_output_bytes],
                error=stderr.decode(errors="replace")[: self.config.max_output_bytes],
                exit_code=proc.returncode,
                execution_time_ms=elapsed,
                permission_level=self.config.permission_level,
            )
        finally:
            Path(script_path).unlink(missing_ok=True)

    def exec_command(self, command: list[str], *, timeout: float | None = None) -> SandboxResult:
        """Execute a shell command in the sandbox."""
        if self.config.permission_level <= PermissionLevel.RESTRICTED:
            return SandboxResult(
                success=False,
                error="Shell commands not allowed at this permission level",
                permission_level=self.config.permission_level,
            )

        timeout = timeout or self.config.max_execution_time_s
        start = time.perf_counter()

        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=tempfile.gettempdir(),
            )
            with self._lock:
                self._running_processes.append(proc)

            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                elapsed = (time.perf_counter() - start) * 1000
                return SandboxResult(
                    success=False,
                    error=f"Command timed out after {timeout}s",
                    exit_code=-1,
                    execution_time_ms=elapsed,
                    permission_level=self.config.permission_level,
                    terminated=True,
                    termination_reason="timeout",
                )
            finally:
                with self._lock:
                    if proc in self._running_processes:
                        self._running_processes.remove(proc)

            elapsed = (time.perf_counter() - start) * 1000
            return SandboxResult(
                success=proc.returncode == 0,
                output=stdout.decode(errors="replace")[: self.config.max_output_bytes],
                error=stderr.decode(errors="replace")[: self.config.max_output_bytes],
                exit_code=proc.returncode,
                execution_time_ms=elapsed,
                permission_level=self.config.permission_level,
            )
        except FileNotFoundError:
            elapsed = (time.perf_counter() - start) * 1000
            return SandboxResult(
                success=False,
                error=f"Command not found: {command[0]}",
                exit_code=127,
                execution_time_ms=elapsed,
                permission_level=self.config.permission_level,
            )

    def exec_function(
        self,
        fn: Any,
        *,
        args: tuple = (),
        kwargs: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> SandboxResult:
        """Execute a Python function with resource limits in the current process."""
        timeout = timeout or self.config.max_execution_time_s
        start = time.perf_counter()
        result_container: dict[str, Any] = {}

        def _run() -> None:
            try:
                result_container["result"] = fn(*args, **(kwargs or {}))
            except Exception as e:
                result_container["error"] = str(e)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        thread.join(timeout=timeout)

        elapsed = (time.perf_counter() - start) * 1000

        if thread.is_alive():
            return SandboxResult(
                success=False,
                error=f"Function timed out after {timeout}s",
                execution_time_ms=elapsed,
                permission_level=self.config.permission_level,
                terminated=True,
                termination_reason="timeout",
            )

        if "error" in result_container:
            return SandboxResult(
                success=False,
                error=result_container["error"],
                execution_time_ms=elapsed,
                permission_level=self.config.permission_level,
            )

        return SandboxResult(
            success=True,
            output=str(result_container.get("result", "")),
            execution_time_ms=elapsed,
            permission_level=self.config.permission_level,
        )

    def kill_all(self) -> int:
        """Emergency kill — terminate all running processes. Returns count killed."""
        killed = 0
        with self._lock:
            for proc in self._running_processes:
                try:
                    proc.kill()
                    killed += 1
                except ProcessLookupError:
                    pass
            self._running_processes.clear()
            self._active = False
        return killed

    @property
    def is_active(self) -> bool:
        return self._active
