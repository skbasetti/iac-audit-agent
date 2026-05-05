from __future__ import annotations

import json
from pathlib import Path

import yaml


def parse_terraform_dir(tf_files: list[Path]) -> tuple[list[dict], str]:
    """Parse .tf files into a resource list and combined raw content."""
    resources: list[dict] = []
    raw_parts: list[str] = []

    for tf_file in tf_files:
        content = tf_file.read_text(encoding="utf-8")
        raw_parts.append(f"# === {tf_file.name} ===\n{content}")

        try:
            import hcl2

            with open(tf_file) as f:
                data = hcl2.load(f)

            for block_type, blocks in data.items():
                if block_type == "resource":
                    for resource_type, instances in blocks.items():
                        for resource_name, config in instances.items():
                            resources.append(
                                {
                                    "block_type": "resource",
                                    "resource_type": resource_type,
                                    "resource_name": resource_name,
                                    "config": config,
                                    "file": tf_file.name,
                                }
                            )
                else:
                    resources.append(
                        {
                            "block_type": block_type,
                            "data": blocks,
                            "file": tf_file.name,
                        }
                    )
        except Exception as exc:
            raw_parts.append(f"# [Parse warning: {exc}]")

    return resources, "\n\n".join(raw_parts)


def parse_cloudformation_file(cf_file: Path) -> tuple[list[dict], str]:
    """Parse a CloudFormation template into a resource list and raw content."""
    content = cf_file.read_text(encoding="utf-8")
    resources: list[dict] = []

    try:
        data = json.loads(content) if cf_file.suffix == ".json" else yaml.safe_load(content)

        for logical_id, resource_def in (data.get("Resources") or {}).items():
            resources.append(
                {
                    "block_type": "resource",
                    "resource_type": resource_def.get("Type", "unknown"),
                    "resource_name": logical_id,
                    "config": resource_def.get("Properties", {}),
                    "file": cf_file.name,
                }
            )
    except Exception:
        pass

    return resources, content
