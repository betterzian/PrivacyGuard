"""CLI for migrating a legacy repository payload into the v2 schema."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from privacyguard.infrastructure.repository.migration_v2 import (  # noqa: E402
    build_ok_summary,
    migrate_legacy_repository,
    read_legacy_payload,
    write_v2_payload,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Path to the legacy JSON payload")
    parser.add_argument("--output", required=True, help="Path to write the migrated v2 JSON payload")
    parser.add_argument(
        "--privacy-mode",
        default="safe_unlinked",
        choices=("safe_unlinked", "link_by_index"),
        help="Migration strategy for flat privacy dictionaries",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = read_legacy_payload(args.input)
    document = migrate_legacy_repository(payload, privacy_mode=args.privacy_mode)
    write_v2_payload(document, args.output)
    print(f"{build_ok_summary(document)} output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
