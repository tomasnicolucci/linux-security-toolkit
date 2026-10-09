from dataclasses import dataclass

from zxcvbn import zxcvbn


@dataclass
class PasswordAnalysis:
    score: int
    strength: str
    length: int
    guesses: int
    crack_time: str
    warnings: list[str]
    recommendations: list[str]


STRENGTH_LEVELS = {
    0: "Very Weak",
    1: "Weak",
    2: "Moderate",
    3: "Strong",
    4: "Very Strong",
}


def analyze_password(password: str) -> PasswordAnalysis:
    if not password:
        raise ValueError("Password cannot be empty.")

    result = zxcvbn(password)

    score = result["score"]
    feedback = result["feedback"]

    warnings = []
    recommendations = []

    if feedback["warning"]:
        warnings.append(feedback["warning"])

    recommendations.extend(feedback["suggestions"])

    if len(password) < 12:
        recommendations.append(
            "Use at least 12 characters, preferably 15 or more."
        )

    if score < 3 and not recommendations:
        recommendations.append(
            "Use a longer, randomly generated password or passphrase."
        )

    warnings = list(dict.fromkeys(warnings))
    recommendations = list(dict.fromkeys(recommendations))

    return PasswordAnalysis(
        score=score,
        strength=STRENGTH_LEVELS[score],
        length=len(password),
        guesses=result["guesses"],
        crack_time=result["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
        warnings=warnings,
        recommendations=recommendations,
    )