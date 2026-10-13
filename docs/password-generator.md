# Password Generator — Usage Guide

The Password Generator creates cryptographically secure random passwords using Python's `secrets` module.

### 1. Interactive mode

```bash
docker compose run --rm -it security-toolkit password generate
```

The tool prompts for the password length and character types.

### 2. Generate a password directly

```bash
docker compose run --rm security-toolkit password generate --length 20
```

The default configuration includes uppercase letters, lowercase letters, digits, and symbols.

### 3. Customize character types

```bash
docker compose run --rm security-toolkit password generate --length 16 --no-symbols
```

Available options:

| Option | Description |
|---|---|
| `--length` | Password length |
| `--uppercase` / `--no-uppercase` | Enable or disable uppercase letters |
| `--lowercase` / `--no-lowercase` | Enable or disable lowercase letters |
| `--digits` / `--no-digits` | Enable or disable numbers |
| `--symbols` / `--no-symbols` | Enable or disable special characters |

### 4. Validation

- Minimum password length: 8 characters.
- At least one character type must be enabled.
- Every enabled character type is guaranteed to appear at least once.
- Invalid configurations produce an error.

### Important notes

- Passwords are generated using a cryptographically secure random number generator.
- Generated passwords are not stored by the toolkit.
- Passwords printed to the terminal may remain visible in terminal logs or scrollback.
- Longer passwords generally provide better resistance to brute-force attacks.