"""Tests for the CLI module."""

from click.testing import CliRunner

from agenttrust.cli import cli


class TestCLI:
    def test_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "AgentTrust" in result.output

    def test_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_init_langchain(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["init", "--framework", "langchain"])
        assert result.exit_code == 0
        assert "AgentTrust" in result.output
        assert "langchain" in result.output
        assert "3 lines" in result.output
        assert "import agenttrust" in result.output

    def test_init_crewai(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["init", "--framework", "crewai"])
        assert result.exit_code == 0
        assert "crewai" in result.output

    def test_init_autogen(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["init", "--framework", "autogen"])
        assert result.exit_code == 0
        assert "autogen" in result.output

    def test_status(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["status"])
        assert result.exit_code == 0
        assert "Fleet Status" in result.output
        assert "finance-bot-prod" in result.output

    def test_config(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["config"])
        assert result.exit_code == 0
        assert "Configuration" in result.output

    def test_monitor_no_live(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["monitor"])
        assert result.exit_code == 0
        assert "--live" in result.output

    def test_monitor_live_with_duration(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["monitor", "--live", "--duration", "2"])
        assert result.exit_code == 0
