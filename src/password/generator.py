import secrets
import string


def generate_password(
    length: int,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    if length < 8:
        raise ValueError("Password length must be at least 8 characters.")

    character_groups = []

    if use_uppercase:
        character_groups.append(string.ascii_uppercase)

    if use_lowercase:
        character_groups.append(string.ascii_lowercase)

    if use_digits:
        character_groups.append(string.digits)

    if use_symbols:
        character_groups.append(string.punctuation)

    if not character_groups:
        raise ValueError("At least one character type must be enabled.")

    if length < len(character_groups):
        raise ValueError(
            "Password length must be at least the number of selected character types."
        )

    password = [
        secrets.choice(group)
        for group in character_groups
    ]

    all_characters = "".join(character_groups)

    password.extend(
        secrets.choice(all_characters)
        for _ in range(length - len(password))
    )

    secrets.SystemRandom().shuffle(password)

    return "".join(password)
