MAX_TEXT_LENGTH = 200


def clean_text(
    value: object,
    limit: int = MAX_TEXT_LENGTH,
) -> str | None:
    """
    Make untrusted text safe to print in a terminal.

    Values coming from DNS, RDAP or input files may contain control
    characters or escape sequences. Nonprintable characters are
    replaced by spaces, whitespace is collapsed and the length is
    limited.
    """
    if not isinstance(value, str):
        return None

    text = "".join(
        character if character.isprintable() else " "
        for character in value
    )

    text = " ".join(text.split())

    if not text:
        return None

    return text[:limit]