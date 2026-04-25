"""Tests for token scanner — env, config, and runtime discovery."""

from __future__ import annotations

import json
import tempfile

import pytest

from agent_guard.tokens.inventory import (
    TokenInventory,
    TokenProvider,
    TokenSource,
    TokenType,
)
from agent_guard.tokens.scanner import TokenScanner


@pytest.fixture
def inventory():
    return TokenInventory()


@pytest.fixture
def scanner(inventory):
    return TokenScanner(inventory=inventory)


class TestEnvironmentScan:
    def test_detects_aws_key(self, scanner):
        env = {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}
        records = scanner.scan_environment(env=env)
        assert len(records) >= 1
        aws = [r for r in records if r.provider == TokenProvider.AWS]
        assert len(aws) == 1
        assert aws[0].source == TokenSource.ENV_VAR
        assert aws[0].source_detail == "AWS_ACCESS_KEY_ID"

    def test_detects_github_token(self, scanner):
        fake_token = "ghp_" + "A" * 40
        env = {"GITHUB_TOKEN": fake_token}
        records = scanner.scan_environment(env=env)
        gh = [r for r in records if r.provider == TokenProvider.GITHUB]
        assert len(gh) == 1
        assert gh[0].token_type == TokenType.PERSONAL_ACCESS_TOKEN

    def test_detects_openai_key(self, scanner):
        env = {"OPENAI_API_KEY": "sk-proj-abc123def456ghi789jkl0"}
        records = scanner.scan_environment(env=env)
        assert len(records) >= 1
        oai = [r for r in records if r.provider == TokenProvider.OPENAI]
        assert len(oai) == 1

    def test_detects_slack_token(self, scanner):
        env = {"SLACK_BOT_TOKEN": "xoxb-123456789012-abcdefghij"}
        records = scanner.scan_environment(env=env)
        slack = [r for r in records if r.provider == TokenProvider.SLACK]
        assert len(slack) == 1
        assert slack[0].token_type == TokenType.OAUTH_TOKEN

    def test_detects_database_url(self, scanner):
        env = {"DATABASE_URL": "postgres://user:pass@host:5432/dbname"}
        records = scanner.scan_environment(env=env)
        db = [r for r in records if r.provider == TokenProvider.DATABASE]
        assert len(db) == 1
        assert db[0].token_type == TokenType.CONNECTION_STRING

    def test_ignores_short_values(self, scanner):
        env = {"SHORT": "abc", "EMPTY": ""}
        records = scanner.scan_environment(env=env)
        assert len(records) == 0

    def test_ignores_non_secret_env_vars(self, scanner):
        env = {"HOME": "/Users/test", "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"}
        records = scanner.scan_environment(env=env)
        assert len(records) == 0

    def test_dotenv_file(self, scanner):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl0\n")
            f.write("# comment\n")
            f.write("EMPTY=\n")
            f.flush()
            records = scanner.scan_environment(env={}, dotenv_path=f.name)
        assert len(records) >= 1

    def test_masked_value_format(self, scanner):
        fake_token = "ghp_" + "X" * 40
        env = {"GITHUB_TOKEN": fake_token}
        records = scanner.scan_environment(env=env)
        assert records[0].masked_value.startswith("ghp_XX")
        assert records[0].masked_value.endswith("XXXX")
        assert "..." in records[0].masked_value


class TestConfigScan:
    def test_scan_mcp_config_with_env_keys(self, scanner):
        config = {
            "mcpServers": {
                "github": {
                    "env": {
                        "GITHUB_TOKEN": "ghp_" + "B" * 40,
                    }
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            f.flush()
            records = scanner.scan_config(f.name)

        assert len(records) >= 1
        assert records[0].source == TokenSource.MCP_CONFIG

    def test_scan_nonexistent_config(self, scanner):
        records = scanner.scan_config("/nonexistent/path.json")
        assert records == []

    def test_scan_invalid_json(self, scanner):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not json{{{")
            f.flush()
            records = scanner.scan_config(f.name)
        assert records == []

    def test_scan_nested_config_values(self, scanner):
        config = {
            "servers": [
                {
                    "name": "test",
                    "credentials": {
                        "api_key": "AIzaSyC" + "a" * 32,
                    },
                }
            ]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            f.flush()
            records = scanner.scan_config(f.name)

        assert len(records) >= 1


class TestRuntimeScan:
    def test_scan_text_finds_aws_key(self, scanner):
        text = "Use this key: AKIAIOSFODNN7EXAMPLE to access S3"
        records = scanner.scan_text(text, source_detail="chat_message")
        aws = [r for r in records if r.provider == TokenProvider.AWS]
        assert len(aws) == 1

    def test_scan_text_with_agent_and_tool(self, scanner):
        text = "Token: ghp_" + "C" * 40
        records = scanner.scan_text(
            text,
            agent_id="agent-1",
            tool_name="github_search",
        )
        assert len(records) >= 1
        assert "agent-1" in records[0].agents
        assert "github_search" in records[0].tools

    def test_scan_dict_params(self, scanner):
        params = {
            "query": "find repos",
            "auth": "ghp_" + "D" * 40,
        }
        records = scanner.scan_dict(
            params,
            source=TokenSource.TOOL_ARGUMENT,
            source_detail="github_search",
            agent_id="agent-2",
            tool_name="github_search",
        )
        assert len(records) >= 1
        assert records[0].source == TokenSource.TOOL_ARGUMENT

    def test_scan_text_no_tokens(self, scanner):
        records = scanner.scan_text("Hello, this is just a regular message.")
        assert len(records) == 0

    def test_dedup_same_token(self, scanner, inventory):
        fake_token = "ghp_" + "E" * 40
        scanner.scan_text(f"first: {fake_token}", agent_id="agent-1")
        scanner.scan_text(f"second: {fake_token}", agent_id="agent-2")
        assert inventory.count == 1
        record = inventory.list_tokens()[0]
        assert record.use_count == 2
        assert "agent-1" in record.agents
        assert "agent-2" in record.agents
