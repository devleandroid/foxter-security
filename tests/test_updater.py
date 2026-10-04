import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

from infra.updater import VERSION_URL, check_for_updates


class UpdateCheckerTests(unittest.TestCase):
    @patch("infra.updater.requests.get")
    def test_requests_bounded_version_and_reports_newer_release(self, get):
        version_file = Path(__file__).resolve().parents[1] / "VERSION"
        current = tuple(
            int(part)
            for part in version_file.read_text(encoding="utf-8").strip().split(".")
        )
        newer_version = f"{current[0]}.{current[1]}.{current[2] + 1}"
        response = MagicMock()
        response.iter_content.return_value = [f"{newer_version}\n".encode("ascii")]
        get.return_value.__enter__.return_value = response

        has_update, version = check_for_updates()

        self.assertTrue(has_update)
        self.assertEqual(version, newer_version)
        get.assert_called_once_with(VERSION_URL, timeout=(3.05, 5), stream=True)
        response.raise_for_status.assert_called_once_with()

    @patch("infra.updater.requests.get")
    def test_does_not_report_older_release_as_an_update(self, get):
        response = MagicMock()
        response.iter_content.return_value = [b"0.0.1\n"]
        get.return_value.__enter__.return_value = response

        has_update, version = check_for_updates()

        self.assertFalse(has_update)
        self.assertEqual(version, "0.0.1")

    @patch("infra.updater.requests.get")
    def test_rejects_non_version_response(self, get):
        response = MagicMock()
        response.iter_content.return_value = [b"run this command"]
        get.return_value.__enter__.return_value = response

        has_update, result = check_for_updates()

        self.assertFalse(has_update)
        self.assertIn("Formato de versão", result)

    @patch("infra.updater.requests.get")
    def test_rejects_oversized_response(self, get):
        response = MagicMock()
        response.iter_content.return_value = [b"1" * 65]
        get.return_value.__enter__.return_value = response

        has_update, result = check_for_updates()

        self.assertFalse(has_update)
        self.assertIn("excede o limite", result)

    @patch("infra.updater.requests.get", side_effect=requests.Timeout("timeout"))
    def test_reports_network_errors(self, get):
        has_update, result = check_for_updates()

        self.assertFalse(has_update)
        self.assertIn("timeout", result)


if __name__ == "__main__":
    unittest.main()
