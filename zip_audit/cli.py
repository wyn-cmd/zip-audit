# Command line front end for zip-audit.
# Exit codes: 0 clean, 1 findings reported, 2 one or more files could not be read.

import argparse
import json
import sys

from .core import MIB, ArchiveError, Limits, SEVERITY_ORDER, audit

VERSION = "0.1.0"


def build_parser():
    parser = argparse.ArgumentParser(
        prog="zip-audit",
        description="Check zip archives for path traversal, symlink entries, duplicate names, encryption and zip bombs.",
    )
    parser.add_argument("archives", nargs="+", help="zip files to inspect")
    parser.add_argument("--json", action="store_true", help="emit machine readable JSON")
    parser.add_argument("--quiet", action="store_true", help="skip archives with no findings")
    parser.add_argument("--max-ratio", type=float, default=100.0, help="per entry expansion factor limit, default 100")
    parser.add_argument("--max-entries", type=int, default=20000, help="entry count limit, default 20000")
    parser.add_argument(
        "--max-uncompressed-mib",
        type=float,
        default=1024.0,
        help="total expanded size limit in MiB, default 1024",
    )
    parser.add_argument("--version", action="version", version="zip-audit " + VERSION)
    return parser


# Human readable block for one archive.
def format_report(report):
    counts = report.counts
    head = (
        report.path
        + ": "
        + str(report.entries)
        + " entries, "
        + str(report.compressed_bytes)
        + " compressed to "
        + str(report.uncompressed_bytes)
        + " expanded bytes"
    )
    lines = [head]
    if report.clean:
        lines.append("  clean")
        return "\n".join(lines)
    ordered = sorted(report.findings, key=lambda f: -SEVERITY_ORDER[f.severity])
    for finding in ordered:
        where = finding.entry if finding.entry else "(archive)"
        lines.append("  [" + finding.severity.upper() + "] " + finding.code + " " + where + ": " + finding.message)
    lines.append(
        "  totals: " + str(counts["high"]) + " high, " + str(counts["medium"]) + " medium, " + str(counts["low"]) + " low"
    )
    return "\n".join(lines)


def main(argv=None):
    args = build_parser().parse_args(argv)
    limits = Limits(
        max_uncompressed_bytes=int(args.max_uncompressed_mib * MIB),
        max_ratio=args.max_ratio,
        max_entries=args.max_entries,
    )

    reports = []
    status = 0
    for path in args.archives:
        try:
            report = audit(path, limits)
        except ArchiveError as exc:
            print(path + ": not a readable zip archive (" + str(exc) + ")", file=sys.stderr)
            status = 2
            continue
        reports.append(report)
        if not report.clean:
            status = max(status, 1)

    if args.json:
        print(json.dumps([r.to_dict() for r in reports], indent=2))
    else:
        blocks = [format_report(r) for r in reports if not (args.quiet and r.clean)]
        if blocks:
            print("\n".join(blocks))

    return status


if __name__ == "__main__":
    sys.exit(main())
