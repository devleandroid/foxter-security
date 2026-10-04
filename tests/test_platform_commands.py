import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.firewall_checker import FirewallChecker
from core.port_checker import PortChecker
from core.user_checker import UserChecker


class NotificationTests(unittest.TestCase):
    @patch("infra.notifier.subprocess.run")
    def test_macos_notification_escapes_content_and_avoids_shell(self, run):
        from infra.notifier import notify

        with patch("infra.notifier.platform.system", return_value="Darwin"):
            notify('Title " & do shell script "bad"', "Message\nline")

        args, kwargs = run.call_args
        self.assertEqual(args[0][:2], ["osascript", "-e"])
        self.assertIn(r'Title \" & do shell script \"bad\"', args[0][2])
        self.assertIn(r"Message\nline", args[0][2])
        self.assertTrue(kwargs["check"])
        self.assertNotIn("shell", kwargs)


class PlatformCommandTests(unittest.TestCase):
    @patch("core.port_checker.subprocess.check_call")
    def test_windows_port_rule_uses_argument_list(self, check_call):
        with patch("core.port_checker.platform.system", return_value="Windows"):
            success, _ = PortChecker().close_port(443)

        self.assertTrue(success)
        command = check_call.call_args.args[0]
        self.assertIsInstance(command, list)
        self.assertIn("localport=443", command)
        self.assertNotIn("shell", check_call.call_args.kwargs)

    @patch("core.port_checker.subprocess.check_call")
    def test_invalid_port_is_rejected_before_running_commands(self, check_call):
        checker = PortChecker()

        for port in (0, 65536, "443", True):
            with self.subTest(port=port):
                success, _ = checker.close_port(port)
                self.assertFalse(success)

        check_call.assert_not_called()

    @patch("core.firewall_checker.subprocess.check_call")
    def test_windows_firewall_enable_uses_argument_list(self, check_call):
        with patch("core.firewall_checker.platform.system", return_value="Windows"):
            success, _ = FirewallChecker().fix()

        self.assertTrue(success)
        self.assertEqual(
            check_call.call_args.args[0],
            ["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
        )
        self.assertNotIn("shell", check_call.call_args.kwargs)

    @patch("core.user_checker.subprocess.check_call")
    def test_windows_user_delete_passes_username_as_single_argument(self, check_call):
        with patch("core.user_checker.platform.system", return_value="Windows"):
            UserChecker().delete_user("example;not-a-command")

        self.assertEqual(
            check_call.call_args.args[0],
            ["net", "user", "example;not-a-command", "/delete"],
        )
        self.assertNotIn("shell", check_call.call_args.kwargs)

    @patch("core.user_checker.subprocess.check_call")
    def test_option_like_username_is_rejected(self, check_call):
        with patch("core.user_checker.platform.system", return_value="Linux"):
            with self.assertRaises(ValueError):
                UserChecker().delete_user("--help")

        check_call.assert_not_called()


class QuarantineTests(unittest.TestCase):
    def test_quarantined_files_have_unique_names_and_private_permissions(self):
        from core.quarantine import quarantine_file

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            quarantine_dir = root / "quarantine"
            sources = [root / "same.txt", root / "another" / "same.txt"]
            sources[0].write_bytes(b"sample one")
            sources[1].parent.mkdir()
            sources[1].write_bytes(b"sample two")

            destinations = [
                quarantine_file(str(source), str(quarantine_dir))
                for source in sources
            ]

            self.assertNotEqual(Path(destinations[0]).name, Path(destinations[1]).name)
            self.assertTrue(all(path.endswith(".quarantined") for path in destinations))
            if os.name != "nt":
                self.assertEqual(quarantine_dir.stat().st_mode & 0o777, 0o700)
                self.assertEqual(Path(destinations[0]).stat().st_mode & 0o777, 0o600)

    def test_quarantine_rejects_symbolic_links(self):
        from core.quarantine import quarantine_file

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("sample")
            link = root / "link.txt"
            try:
                link.symlink_to(source)
            except (OSError, NotImplementedError):
                self.skipTest("Symbolic links are unavailable")

            with self.assertRaises(ValueError):
                quarantine_file(str(link), str(root / "quarantine"))


if __name__ == "__main__":
    unittest.main()
