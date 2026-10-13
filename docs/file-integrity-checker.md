## File Integrity Checker

The File Integrity Checker monitors files and directories using SHA-256 hashes. It detects modified, added, and deleted files by comparing their current state against a saved baseline.

### 1. Create a baseline

```bash
docker compose run --rm security-toolkit integrity create /app/samples --name test --recursive
```

- `/app/samples`: Directory to monitor.
- `--name test`: Baseline identifier.
- `--recursive`: Include subdirectories.
- `--exclude "*.log"`: Optional exclusion pattern (can be repeated).

The baseline is saved at `data/integrity/test.json` and contains the monitored path, file hashes, permissions, and metadata.

### 2. Check file integrity

```bash
docker compose run --rm security-toolkit integrity check --name test
```

The command automatically retrieves the monitored directory from the saved baseline.

Possible results:

| Status | Description |
|---|---|
| `UNCHANGED` | File content and permissions remain unchanged. |
| `MODIFIED` | File content or permissions changed. |
| `ADDED` | A new file was detected. |
| `DELETED` | A previously registered file is missing. |
| `ERROR` | A file could not be verified. |

### 3. Test change detection

**MODIFIED:** Edit `samples/config.txt`, then run `check`.

**ADDED:** Create `samples/new.txt`, then run `check`.

**DELETED:** Run `update` to register `new.txt`, delete the file, then run `check`.

### 4. Update a baseline

After reviewing and accepting detected changes:

```bash
docker compose run --rm security-toolkit integrity update --name test
```

This replaces the previous baseline with the current file state.

### 5. Calculate a file hash

```bash
docker compose run --rm security-toolkit integrity hash /app/samples/config.txt
```

### 6. Export a JSON report

```bash
docker compose run --rm security-toolkit integrity check --name test --output /app/data/integrity/report.json
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No changes detected |
| `1` | Changes detected |
| `2` | Scan or verification errors |

### Important notes

- `--name` identifies a baseline, not an individual file.
- `check` does not modify files or baselines.
- `update` should only be executed after reviewing detected changes.
- Monitored directories are mounted read-only inside Docker.
- Symbolic links are not followed.
- Baselines must be protected against unauthorized modification.