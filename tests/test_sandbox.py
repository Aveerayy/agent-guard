"""Tests for sandbox execution."""

from agent_guard import PermissionLevel, Sandbox


class TestSandbox:
    def test_exec_python(self):
        sandbox = Sandbox(permission_level=PermissionLevel.STANDARD)
        result = sandbox.exec_python("print('hello')")
        assert result.success
        assert "hello" in result.output

    def test_exec_python_error(self):
        sandbox = Sandbox(permission_level=PermissionLevel.STANDARD)
        result = sandbox.exec_python("raise ValueError('boom')")
        assert not result.success

    def test_minimal_blocks_execution(self):
        sandbox = Sandbox(permission_level=PermissionLevel.MINIMAL)
        result = sandbox.exec_python("print('should not run')")
        assert not result.success
        assert "not allowed" in result.error.lower()

    def test_restricted_blocks_commands(self):
        sandbox = Sandbox(permission_level=PermissionLevel.RESTRICTED)
        result = sandbox.exec_command(["echo", "test"])
        assert not result.success

    def test_exec_command(self):
        sandbox = Sandbox(permission_level=PermissionLevel.STANDARD)
        result = sandbox.exec_command(["echo", "hello"])
        assert result.success
        assert "hello" in result.output

    def test_timeout(self):
        sandbox = Sandbox(permission_level=PermissionLevel.STANDARD)
        result = sandbox.exec_python("import time; time.sleep(10)", timeout=0.5)
        assert not result.success
        assert result.terminated

    def test_exec_function(self):
        sandbox = Sandbox(permission_level=PermissionLevel.STANDARD)
        result = sandbox.exec_function(lambda x, y: x + y, args=(2, 3))
        assert result.success
        assert result.output == "5"

    def test_exec_function_error(self):
        sandbox = Sandbox(permission_level=PermissionLevel.STANDARD)

        def bad_func():
            raise RuntimeError("fail")

        result = sandbox.exec_function(bad_func)
        assert not result.success
        assert "fail" in result.error
