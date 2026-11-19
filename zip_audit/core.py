# Core checks for zip archives.
# Pure standard library, no third party imports, so this runs on a bare python3.

import re
import stat
import zipfile
from dataclasses import dataclass

MIB = 1024 * 1024
GIB = 1024 * MIB

# Higher number wins when the report picks its overall severity.
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


# Raised when a path cannot be opened as a zip archive at all.
# The caller turns this into a non zero exit instead of a traceback.
class ArchiveError(Exception):
    pass


@dataclass
class Limits:
    # Largest total expanded size we accept before flagging a bomb.
    max_uncompressed_bytes: int = 1 * GIB
    # Expansion factor, uncompressed divided by compressed, per entry.
    max_ratio: float = 100.0
    # Number of entries in the central directory.
    max_entries: int = 20000
    # Entries smaller than this are never judged on ratio, to avoid noise.
    ratio_min_bytes: int = 1 * MIB


@dataclass
class Finding:
    code: str
    severity: str
    entry: str
    message: str

    def as_dict(self):
        return {
            "code": self.code,
            "severity": self.severity,
            "entry": self.entry,
            "message": self.message,
        }


@dataclass
class Report:
    path: str
    entries: int
    compressed_bytes: int
    uncompressed_bytes: int
    findings: list

    @property
    def clean(self):
        return not self.findings

    @property
    def worst(self):
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    @property
    def counts(self):
        out = {"high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            out[finding.severity] += 1
        return out

    def to_dict(self):
        return {
            "path": self.path,
            "entries": self.entries,
            "compressed_bytes": self.compressed_bytes,
            "uncompressed_bytes": self.uncompressed_bytes,
            "worst": self.worst,
            "counts": self.counts,
            "findings": [f.as_dict() for f in self.findings],
        }


# Split an entry name on either separator so windows style paths are caught too.
def _parts(name):
    return [p for p in re.split(r"[\\/]", name)]


# Name based checks: absolute paths, drive letters, .. traversal, backslashes.
def _name_findings(name):
    out = []
    if not name:
        return out
    if name.startswith("/") or name.startswith("\\"):
        out.append(Finding("absolute-path", "high", name, "entry name starts at the filesystem root"))
    elif len(name) > 1 and name[1] == ":" and name[0].isalpha():
        out.append(Finding("absolute-path", "high", name, "entry name carries a drive letter"))
    parts = _parts(name)
    if ".." in parts:
        out.append(Finding("path-traversal", "high", name, "entry name climbs above the extraction root with .."))
    if "\\" in name:
        out.append(Finding("backslash-separator", "low", name, "entry uses backslash separators"))
    return out


# Read the archive and return a Report. Raises ArchiveError on unreadable input.
def audit(path, limits=None):
    limits = limits or Limits()
    try:
        with zipfile.ZipFile(path) as handle:
            infos = handle.infolist()
    except (zipfile.BadZipFile, OSError) as exc:
        raise ArchiveError(str(exc)) from exc

    findings = []
    seen = {}
    seen_lower = {}
    total_uncompressed = 0
    total_compressed = 0

    for info in infos:
        name = info.filename
        total_uncompressed += info.file_size
        total_compressed += info.compress_size

        findings.extend(_name_findings(name))

        if name in seen:
            findings.append(Finding("duplicate-entry", "medium", name, "name appears more than once in the archive"))
        else:
            seen[name] = 1

        lowered = name.lower()
        if lowered in seen_lower and seen_lower[lowered] != name:
            findings.append(
                Finding("case-collision", "medium", name, "differs only by case from " + seen_lower[lowered])
            )
        else:
            seen_lower.setdefault(lowered, name)

        # The unix mode sits in the high half of external_attr. A symlink entry
        # is dangerous because extraction can point it outside the target tree.
        mode = info.external_attr >> 16
        if mode and stat.S_ISLNK(mode):
            findings.append(
                Finding("symlink-entry", "high", name, "entry is a symlink and may escape the extraction directory")
            )

        if info.flag_bits & 0x1:
            findings.append(Finding("encrypted-entry", "low", name, "entry is encrypted"))

        if info.file_size >= limits.ratio_min_bytes:
            if info.compress_size == 0:
                findings.append(
                    Finding(
                        "compression-ratio",
                        "high",
                        name,
                        "reports " + str(info.file_size) + " bytes with a zero compressed size",
                    )
                )
            else:
                ratio = info.file_size / info.compress_size
                if ratio > limits.max_ratio:
                    findings.append(
                        Finding(
                            "compression-ratio",
                            "high",
                            name,
                            "expands " + str(round(ratio)) + "x (" + str(info.compress_size) + " to " + str(info.file_size) + " bytes)",
                        )
                    )

        if name.endswith("/") and info.file_size > 0:
            findings.append(
                Finding("directory-with-data", "low", name, "directory entry also carries file data")
            )

        if not name.strip():
            findings.append(Finding("empty-name", "medium", "", "entry has an empty name"))

    if len(infos) > limits.max_entries:
        findings.append(
            Finding(
                "entry-count",
                "medium",
                "",
                str(len(infos)) + " entries exceeds the limit of " + str(limits.max_entries),
            )
        )

    if total_uncompressed > limits.max_uncompressed_bytes:
        findings.append(
            Finding(
                "total-size",
                "high",
                "",
                "expands to " + str(total_uncompressed) + " bytes, over the limit of " + str(limits.max_uncompressed_bytes),
            )
        )

    return Report(
        path=str(path),
        entries=len(infos),
        compressed_bytes=total_compressed,
        uncompressed_bytes=total_uncompressed,
        findings=findings,
    )
