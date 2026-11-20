"""The MCP server speaks JSON-RPC over stdio and maps tools onto the netdoc CLI."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests.fakerouter import SCRIPTS


def session(*msgs):
    env = dict(os.environ, NETDOC_HOME=tempfile.mkdtemp(prefix="netdoc-mcp-"))
    p = subprocess.run([sys.executable, os.path.join(SCRIPTS, "netdoc_mcp.py")], env=env, capture_output=True, text=True,
                       input="\n".join(json.dumps(m) for m in msgs) + "\n", timeout=60)
    return {d["id"]: d for d in map(json.loads, p.stdout.splitlines()) if "id" in d}


def call(i, name, **args):
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}}


class MCP(unittest.TestCase):
    def test_handshake_and_tools(self):
        r = session({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                    {"jsonrpc": "2.0", "method": "notifications/initialized"},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual(r[1]["result"]["serverInfo"]["name"], "network-doctor")
        self.assertIn("Never retry a failed login", r[1]["result"]["instructions"])
        names = {t["name"] for t in r[2]["result"]["tools"]}
        self.assertTrue({"network_diagnose", "router_status", "router_write", "router_password_setup"} <= names)
        w = next(t for t in r[2]["result"]["tools"] if t["name"] == "router_write")
        self.assertTrue(w["annotations"]["destructiveHint"])

    def test_demo_calls_and_write_plan(self):
        r = session(call(1, "network_diagnose", demo=True), call(2, "router_write", demo=True, target="wifi.2g",
                                                                 fields={"channel": "1"}),
                    call(3, "nope"), call(4, "router_get", demo=True))
        d = json.loads(r[1]["result"]["content"][0]["text"])
        self.assertEqual(d["findings"][0]["area"], "bufferbloat")
        plan = json.loads(r[2]["result"]["content"][0]["text"])
        self.assertFalse(plan["applied"])
        self.assertEqual(plan["current"], {"channel": "11"})
        self.assertIn("error", r[3])
        self.assertTrue(r[4]["result"]["isError"])  # missing required target -> argparse error, reported not crashed


if __name__ == "__main__":
    unittest.main()
