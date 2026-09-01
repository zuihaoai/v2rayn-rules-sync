#!/usr/bin/env python3
"""Convert Shadowrocket [Rule] sections to v2rayN routing-rule JSON."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable


UPSTREAM_BASE = (
    "https://raw.githubusercontent.com/"
    "Johnshall/Shadowrocket-ADBlock-Rules-Forever/release"
)

DEFAULT_RULE_FILES = (
    "sr_ad_only.conf",
    "sr_adb.conf",
    "sr_backcn.conf",
    "sr_backcn_ad.conf",
    "sr_cnip.conf",
    "sr_cnip_ad.conf",
    "sr_direct_banad.conf",
    "sr_proxy_banad.conf",
    "sr_top500_banlist.conf",
    "sr_top500_banlist_ad.conf",
    "sr_top500_whitelist.conf",
    "sr_top500_whitelist_ad.conf",
)

POLICY_MAP = {
    "direct": "direct",
    "proxy": "proxy",
    "reject": "block",
    "reject-drop": "block",
    "reject-tinygif": "block",
}

DOMAIN_TYPES = {
    "DOMAIN": "full:",
    "DOMAIN-SUFFIX": "domain:",
    "DOMAIN-KEYWORD": "keyword:",
}

IP_TYPES = {"IP-CIDR", "IP-CIDR6"}
UNSUPPORTED_TYPES = {
    "AND",
    "DST-PORT",
    "IP-ASN",
    "NOT",
    "OR",
    "PROCESS-NAME",
    "SCRIPT",
    "URL-REGEX",
    "USER-AGENT",
}


@dataclass
class ConversionReport:
    source: str
    input_rules: int = 0
    output_groups: int = 0
    skipped_rules: int = 0
    expanded_rule_sets: int = 0
    warnings: list[str] = field(default_factory=list)


class RuleBuilder:
    def __init__(self) -> None:
        self.rules: list[dict] = []

    def add_values(self, field_name: str, values: Iterable[str], outbound: str) -> None:
        clean_values = [value for value in values if value]
        if not clean_values:
            return

        previous = self.rules[-1] if self.rules else None
        if (
            previous
            and previous.get("outboundTag") == outbound
            and field_name in previous
            and set(previous) == {"outboundTag", field_name}
        ):
            previous[field_name].extend(clean_values)
            return

        self.rules.append({"outboundTag": outbound, field_name: clean_values})

    def add_final(self, outbound: str) -> None:
        self.rules.append(
            {
                "remarks": "FINAL fallback",
                "outboundTag": outbound,
                "port": "0-65535",
                "network": "tcp,udp",
            }
        )


def read_text(source: str) -> str:
    if re.match(r"^https?://", source, re.IGNORECASE):
        request = urllib.request.Request(
            source,
            headers={"User-Agent": "shadowrocket-to-v2rayn/1.0"},
        )
        with urllib.request.urlopen(request, timeout=45) as response:
            return response.read().decode("utf-8-sig")
    return Path(source).read_text(encoding="utf-8-sig")


def iter_rule_lines(text: str) -> Iterable[tuple[int, str]]:
    lines = text.splitlines()
    has_rule_section = any(line.strip().lower() == "[rule]" for line in lines)
    in_rule_section = not has_rule_section

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if line.lower() == "[rule]":
            in_rule_section = True
            continue
        if in_rule_section and line.startswith("[") and line.endswith("]"):
            break
        if not in_rule_section or not line or line.startswith(("#", ";", "//")):
            continue
        yield line_number, line


def parse_csv_line(line: str) -> list[str]:
    return [part.strip() for part in next(csv.reader([line], skipinitialspace=True))]


def normalize_policy(policy: str) -> str | None:
    policy = re.split(r"\s+#", policy, maxsplit=1)[0].strip().lower()
    return POLICY_MAP.get(policy)


def convert_text(
    text: str,
    source: str,
    *,
    fetcher: Callable[[str], str] = read_text,
    forced_policy: str | None = None,
    depth: int = 0,
    builder: RuleBuilder | None = None,
    report: ConversionReport | None = None,
) -> tuple[list[dict], ConversionReport]:
    if depth > 4:
        raise ValueError(f"RULE-SET nesting is too deep: {source}")

    builder = builder or RuleBuilder()
    report = report or ConversionReport(source=source)

    for line_number, line in iter_rule_lines(text):
        fields = parse_csv_line(line)
        if not fields:
            continue

        rule_type = fields[0].upper()
        report.input_rules += 1

        if rule_type == "FINAL":
            policy_text = forced_policy or (fields[1] if len(fields) > 1 else "")
            outbound = normalize_policy(policy_text)
            if outbound is None:
                report.skipped_rules += 1
                report.warnings.append(
                    f"{source}:{line_number}: unsupported policy {policy_text!r}"
                )
            else:
                builder.add_final(outbound)
            continue

        if rule_type == "RULE-SET":
            if len(fields) < 2:
                report.skipped_rules += 1
                report.warnings.append(f"{source}:{line_number}: malformed RULE-SET")
                continue
            policy_text = forced_policy or (fields[2] if len(fields) > 2 else "")
            outbound = normalize_policy(policy_text)
            if outbound is None:
                report.skipped_rules += 1
                report.warnings.append(
                    f"{source}:{line_number}: unsupported policy {policy_text!r}"
                )
                continue
            nested_source = fields[1]
            try:
                nested_text = fetcher(nested_source)
                report.expanded_rule_sets += 1
                convert_text(
                    nested_text,
                    nested_source,
                    fetcher=fetcher,
                    forced_policy=outbound,
                    depth=depth + 1,
                    builder=builder,
                    report=report,
                )
            except Exception as exc:  # Network failures should be visible in the manifest.
                report.skipped_rules += 1
                report.warnings.append(
                    f"{source}:{line_number}: failed to expand {nested_source}: {exc}"
                )
            continue

        if rule_type == "DOMAIN-SET":
            if len(fields) < 2:
                report.skipped_rules += 1
                report.warnings.append(f"{source}:{line_number}: malformed DOMAIN-SET")
                continue
            policy_text = forced_policy or (fields[2] if len(fields) > 2 else "")
            outbound = normalize_policy(policy_text)
            if outbound is None:
                report.skipped_rules += 1
                report.warnings.append(
                    f"{source}:{line_number}: unsupported policy {policy_text!r}"
                )
                continue
            nested_source = fields[1]
            try:
                nested_domains = [
                    candidate.strip()
                    for _, candidate in iter_rule_lines(fetcher(nested_source))
                    if "," not in candidate
                ]
                builder.add_values(
                    "domain", (f"domain:{domain}" for domain in nested_domains), outbound
                )
                report.expanded_rule_sets += 1
            except Exception as exc:
                report.skipped_rules += 1
                report.warnings.append(
                    f"{source}:{line_number}: failed to expand {nested_source}: {exc}"
                )
            continue

        if len(fields) < 2:
            report.skipped_rules += 1
            report.warnings.append(f"{source}:{line_number}: malformed {rule_type} rule")
            continue

        policy_text = forced_policy or (fields[2] if len(fields) > 2 else "")
        outbound = normalize_policy(policy_text)
        if outbound is None:
            report.skipped_rules += 1
            report.warnings.append(
                f"{source}:{line_number}: unsupported policy {policy_text!r}"
            )
            continue

        value = fields[1].strip()
        if rule_type in DOMAIN_TYPES:
            builder.add_values("domain", [f"{DOMAIN_TYPES[rule_type]}{value}"], outbound)
        elif rule_type in IP_TYPES:
            builder.add_values("ip", [value], outbound)
        elif rule_type == "GEOIP":
            builder.add_values("ip", [f"geoip:{value.lower()}"], outbound)
        elif rule_type in UNSUPPORTED_TYPES:
            report.skipped_rules += 1
            report.warnings.append(
                f"{source}:{line_number}: {rule_type} has no equivalent v2rayN/Xray rule"
            )
        else:
            report.skipped_rules += 1
            report.warnings.append(
                f"{source}:{line_number}: unknown rule type {rule_type}"
            )

    report.output_groups = len(builder.rules)
    return builder.rules, report


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def convert_source(source: str, output: Path) -> ConversionReport:
    rules, report = convert_text(read_text(source), source)
    write_json(output, rules)
    return report


def build_template(publish_base: str, rule_files: Iterable[str]) -> dict:
    base = publish_base.rstrip("/")
    return {
        "version": "Johnshall-v2rayN",
        "routingItems": [
            {
                "remarks": Path(rule_file).stem,
                "url": f"{base}/{Path(rule_file).with_suffix('.json').name}",
                "ruleSet": "",
                "domainStrategy": "IPIfNonMatch",
                "domainStrategy4Singbox": "",
            }
            for rule_file in rule_files
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--all", action="store_true", help="convert all upstream sr_*.conf files")
    mode.add_argument("--input", help="local path or HTTP(S) URL to one Shadowrocket file")
    parser.add_argument("--output", help="output JSON path for --input mode")
    parser.add_argument("--output-dir", default="rules", help="output directory for --all mode")
    parser.add_argument("--upstream-base", default=UPSTREAM_BASE)
    parser.add_argument(
        "--publish-base",
        help="public Raw base URL used to generate template.json in --all mode",
    )
    parser.add_argument(
        "--fail-on-warning",
        action="store_true",
        help="return a non-zero status if any rule was skipped",
    )
    args = parser.parse_args()

    reports: list[dict] = []
    warning_count = 0

    if args.input:
        if not args.output:
            parser.error("--output is required with --input")
        report = convert_source(args.input, Path(args.output))
        reports.append(report.__dict__)
        warning_count += len(report.warnings)
    else:
        output_dir = Path(args.output_dir)
        for file_name in DEFAULT_RULE_FILES:
            source = f"{args.upstream_base.rstrip('/')}/{file_name}"
            output = output_dir / Path(file_name).with_suffix(".json")
            print(f"Converting {source} -> {output}", file=sys.stderr)
            report = convert_source(source, output)
            reports.append(report.__dict__)
            warning_count += len(report.warnings)

        manifest = {
            "upstream": args.upstream_base,
            "format": "v2rayN routing rules",
            "files": reports,
        }
        write_json(output_dir / "manifest.json", manifest)
        if args.publish_base:
            write_json(
                output_dir / "template.json",
                build_template(args.publish_base, DEFAULT_RULE_FILES),
            )

    print(json.dumps(reports, ensure_ascii=False, indent=2))
    if args.fail_on_warning and warning_count:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
