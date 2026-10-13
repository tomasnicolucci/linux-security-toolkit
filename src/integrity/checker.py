from dataclasses import dataclass, field

from src.integrity.scanner import ScanResult


@dataclass
class IntegrityReport:
    unchanged: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "summary": {
                "unchanged": len(self.unchanged),
                "modified": len(self.modified),
                "added": len(self.added),
                "deleted": len(self.deleted),
                "errors": len(self.errors),
            },
            "unchanged": self.unchanged,
            "modified": self.modified,
            "added": self.added,
            "deleted": self.deleted,
            "errors": self.errors,
        }


def compare_integrity(
    baseline_files: dict,
    current: ScanResult,
) -> IntegrityReport:
    report = IntegrityReport(errors=dict(current.errors))

    for path, previous in baseline_files.items():
        if path in current.errors:
            continue

        if path not in current.files:
            if any(
                path == error_path
                or path.startswith(error_path.rstrip("/") + "/")
                for error_path in current.errors
            ):
                continue

            report.deleted.append(path)
            continue

        current_record = current.files[path]

        if (
            previous["sha256"] != current_record["sha256"]
            or previous["permissions"] != current_record["permissions"]
        ):
            report.modified.append(path)
        else:
            report.unchanged.append(path)

    for path in current.files:
        if path not in baseline_files:
            report.added.append(path)

    report.unchanged.sort()
    report.modified.sort()
    report.added.sort()
    report.deleted.sort()

    return report
