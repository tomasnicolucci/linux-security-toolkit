from dataclasses import dataclass, field
from datetime import tzinfo
from pathlib import Path

from src.logs.models import SecurityEvent
from src.logs.parser import parse_log_line
from src.logs.reader import discover_log_files, read_log_lines


@dataclass
class LoadResult:
    events: list[SecurityEvent] = field(default_factory=list)
    files_processed: list[str] = field(default_factory=list)
    lines_processed: int = 0
    lines_unparsed: int = 0
    errors: dict[str, str] = field(default_factory=dict)


def load_events(
    target: Path,
    recursive: bool,
    year: int | None,
    tz: tzinfo,
) -> LoadResult:
    """
    Read and parse logs with the same reader and parser used by the
    log analyzer, so both modules count exactly the same events.
    """
    discovered = discover_log_files(target, recursive=recursive)

    result = LoadResult(errors=dict(discovered.errors))

    for path in discovered.files:
        try:
            for line in read_log_lines(path):
                result.lines_processed += 1

                try:
                    event = parse_log_line(line, year=year, tz=tz)
                except (ValueError, OverflowError) as error:
                    result.lines_unparsed += 1
                    result.errors[
                        f"{path}:{line.line_number}"
                    ] = str(error)
                    continue

                if event is None:
                    result.lines_unparsed += 1
                    continue

                result.events.append(event)

            result.files_processed.append(str(path))

        except (OSError, ValueError, EOFError) as error:
            result.errors[str(path)] = str(error)

    return result