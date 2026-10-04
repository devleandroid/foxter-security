import unittest
from unittest.mock import MagicMock, patch

import requests

from infra.updater import VERSION_URL, check_for_updates


class UpdateCheckerTests(unittest.TestCase):
    @patch("infra.updater.requests.get")
    def test_requests_bounded_version_and_reports_newer_release(self, get):
        response = MagicMock()
        response.iter_content.return_value = [b"1.0.4\n"]
        get.return_value.__enter__.return_value = response

        has_update, version = check_for_updates()

        self.assertTrue(has_update)
        self.assertEqual(version, "1.0.4")
        get.assert_called_once_with(VERSION_URL, timeout=(3.05, 5), stream=True)
        response.raise_for_status.assert_called_once_with()

    @patch("infra.updater.requests.get")
    def test_does_not_report_older_release_as_an_update(self, get):
        response = MagicMock()
        response.iter_content.return_value = [b"1.0.2\n"]
        get.return_value.__enter__.return_value = response

        has_update, version = check_for_updates()

        self.assertFalse(has_update)
        self.assertEqual(version, "1.0.2")

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
