# Password Analyzer — Usage Guide

The Password Analyzer evaluates password strength using the `zxcvbn` library. It identifies predictable patterns, common passwords, and potential weaknesses.

### 1. Analyze a password

```bash
docker compose run --rm -it security-toolkit password analyze
```

The tool requests a password through a hidden terminal prompt.

### 2. Analysis results

The output includes:

| Field | Description |
|---|---|
| Length | Number of characters |
| Score | Strength score from 0 to 4 |
| Strength | Human-readable strength classification |
| Guesses | Estimated number of guesses required |
| Crack time | Estimated offline cracking time |
| Warnings | Detected weaknesses |
| Recommendations | Suggestions to improve security |

### 3. Strength levels

| Score | Classification |
|---|---|
| `0` | Very Weak |
| `1` | Weak |
| `2` | Moderate |
| `3` | Strong |
| `4` | Very Strong |

### 4. Example testing scenarios

Try entering passwords with different characteristics:

- A common password such as `password123`.
- A short password containing symbols.
- A longer password containing predictable patterns.
- A randomly generated password with 20 or more characters.

Compare the resulting scores and recommendations.

### Important notes

- Password input is hidden using `getpass`.
- Passwords are analyzed locally and are not transmitted to external services.
- The tool does not store analyzed passwords.
- Crack-time estimates are approximate and depend on the assumed attack conditions.
- A high score does not guarantee that a password is uncompromised.
- Avoid testing real production passwords in environments you do not fully trust.