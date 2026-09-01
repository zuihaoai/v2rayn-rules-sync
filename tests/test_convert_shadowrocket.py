import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "convert_shadowrocket.py"
SPEC = importlib.util.spec_from_file_location("convert_shadowrocket", MODULE_PATH)
converter = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = converter
SPEC.loader.exec_module(converter)


class ConvertShadowrocketTests(unittest.TestCase):
    def test_maps_supported_rules_and_preserves_order(self):
        source = """
[Rule]
DOMAIN-SUFFIX,example.com,PROXY
DOMAIN-KEYWORD,tracker,REJECT
IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
GEOIP,CN,DIRECT
FINAL,PROXY
"""
        rules, report = converter.convert_text(source, "fixture.conf")

        self.assertEqual(
            rules,
            [
                {"outboundTag": "proxy", "domain": ["domain:example.com"]},
                {"outboundTag": "block", "domain": ["keyword:tracker"]},
                {"outboundTag": "direct", "ip": ["10.0.0.0/8", "geoip:cn"]},
                {
                    "remarks": "FINAL fallback",
                    "outboundTag": "proxy",
                    "port": "0-65535",
                    "network": "tcp,udp",
                },
            ],
        )
        self.assertEqual(report.skipped_rules, 0)

    def test_expands_remote_rule_set_with_outer_policy(self):
        source = """
[Rule]
RULE-SET,https://example.test/apple.list,PROXY
FINAL,DIRECT
"""
        remote = """
# remote rules
DOMAIN-SUFFIX,apple.news
IP-CIDR,1.2.3.0/24
"""

        rules, report = converter.convert_text(
            source,
            "fixture.conf",
            fetcher=lambda _: remote,
        )

        self.assertEqual(rules[0], {"outboundTag": "proxy", "domain": ["domain:apple.news"]})
        self.assertEqual(rules[1], {"outboundTag": "proxy", "ip": ["1.2.3.0/24"]})
        self.assertEqual(report.expanded_rule_sets, 1)
        self.assertEqual(report.skipped_rules, 0)

    def test_reports_non_equivalent_shadowrocket_rules(self):
        source = """
[Rule]
URL-REGEX,^https://example.com/ad,REJECT
USER-AGENT,Example*,DIRECT
"""
        rules, report = converter.convert_text(source, "fixture.conf")

        self.assertEqual(rules, [])
        self.assertEqual(report.skipped_rules, 2)
        self.assertEqual(len(report.warnings), 2)


if __name__ == "__main__":
    unittest.main()
