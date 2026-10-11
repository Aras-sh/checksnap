import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_manifests_parse_and_match():
    plugin = json.loads((ROOT / ".claude-plugin/plugin.json").read_text())
    market = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())
    assert plugin["name"] == "checksnap" and plugin["version"] == "0.1.1" and plugin["license"] == "MIT"
    assert plugin["mcpServers"]["checksnap"]["args"] == ["${CLAUDE_PLUGIN_ROOT}/mcp_server.py"]
    key = plugin["userConfig"]["subq_api_key"]
    assert key["sensitive"] is True and key["required"] is False
    assert plugin["mcpServers"]["checksnap"]["env"]["SUBQ_API_KEY"] == "${user_config.subq_api_key}"
    assert market["plugins"][0]["name"] == "checksnap"


def test_skill_is_short_and_named():
    text = (ROOT / "skills/bugscan/SKILL.md").read_text()
    assert text.startswith("---\nname: bugscan\n") and len(text.splitlines()) < 60
