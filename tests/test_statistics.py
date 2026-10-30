import string
import unittest
from unittest import mock

from src.password.analyzer import STRENGTH_LEVELS, analyze_password
from src.password.generator import generate_password
from tests.helpers import real_zxcvbn_available


def fake_result(score=3, warning="", suggestions=(), guesses=10**9):
    return {
        "score": score,
        "guesses": guesses,
        "feedback": {
            "warning": warning,
            "suggestions": list(suggestions),
        },
        "crack_times_display": {
            "offline_slow_hashing_1e4_per_second": "3 days",
        },
    }


class GeneratorTests(unittest.TestCase):
    def test_returns_requested_length(self):
        for length in (8, 12, 64, 200):
            with self.subTest(length=length):
                self.assertEqual(len(generate_password(length)), length)

    def test_rejects_short_length(self):
        with self.assertRaises(ValueError):
            generate_password(7)

    def test_requires_at_least_one_character_type(self):
        with self.assertRaises(ValueError):
            generate_password(
                16,
                use_uppercase=False,
                use_lowercase=False,
                use_digits=False,
                use_symbols=False,
            )

    def test_contains_every_selected_type(self):
        for _ in range(300):
            password = generate_password(8)

            self.assertTrue(any(c in string.ascii_uppercase for c in password))
            self.assertTrue(any(c in string.ascii_lowercase for c in password))
            self.assertTrue(any(c in string.digits for c in password))
            self.assertTrue(any(c in string.punctuation for c in password))

    def test_uses_only_selected_types(self):
        for _ in range(100):
            password = generate_password(
                20,
                use_uppercase=False,
                use_symbols=False,
            )

            self.assertTrue(
                set(password) <= set(string.ascii_lowercase + string.digits)
            )

    def test_passwords_are_not_repeated(self):
        generated = {generate_password(24) for _ in range(200)}

        self.assertEqual(len(generated), 200)


class AnalyzerTests(unittest.TestCase):
    def analyze(self, password, result):
        with mock.patch(
            "src.password.analyzer.zxcvbn",
            return_value=result,
        ):
            return analyze_password(password)

    def test_rejects_empty_password(self):
        with self.assertRaises(ValueError):
            analyze_password("")

    def test_maps_scores_to_strength_labels(self):
        for score, label in STRENGTH_LEVELS.items():
            with self.subTest(score=score):
                analysis = self.analyze(
                    "x" * 20,
                    fake_result(score=score, suggestions=["ok"]),
                )

                self.assertEqual(analysis.score, score)
                self.assertEqual(analysis.strength, label)

    def test_copies_library_feedback(self):
        analysis = self.analyze(
            "x" * 20,
            fake_result(
                score=1,
                warning="Too common.",
                suggestions=["Add another word."],
            ),
        )

        self.assertEqual(analysis.warnings, ["Too common."])
        self.assertEqual(analysis.recommendations, ["Add another word."])
        self.assertEqual(analysis.crack_time, "3 days")
        self.assertEqual(analysis.length, 20)

    def test_short_password_gets_length_recommendation(self):
        analysis = self.analyze("short1", fake_result(score=4))

        self.assertTrue(
            any("12 characters" in item for item in analysis.recommendations)
        )

    def test_long_strong_password_has_no_recommendations(self):
        analysis = self.analyze("x" * 20, fake_result(score=4))

        self.assertEqual(analysis.recommendations, [])
        self.assertEqual(analysis.warnings, [])

    def test_weak_password_without_feedback_gets_generic_advice(self):
        analysis = self.analyze("x" * 20, fake_result(score=2))

        self.assertEqual(len(analysis.recommendations), 1)
        self.assertIn("randomly generated", analysis.recommendations[0])

    def test_removes_duplicate_feedback(self):
        analysis = self.analyze(
            "x" * 20,
            fake_result(
                score=4,
                warning="Same.",
                suggestions=["Same suggestion.", "Same suggestion."],
            ),
        )

        self.assertEqual(analysis.recommendations, ["Same suggestion."])


@unittest.skipUnless(
    real_zxcvbn_available(),
    "The zxcvbn library is not available.",
)
class RealLibraryTests(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        analysis = analyze_password("password")

        self.assertEqual(analysis.score, 0)
        self.assertEqual(analysis.strength, "Very Weak")

    def test_generated_password_is_very_strong(self):
        analysis = analyze_password(generate_password(24))

        self.assertGreaterEqual(analysis.score, 3)


if __name__ == "__main__":
    unittest.main()
