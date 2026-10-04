import unittest

from core.realtime_protection import RansomwareActivityMonitor


class RansomwareActivityMonitorTests(unittest.TestCase):
    def test_alerts_on_ransomware_extension(self):
        monitor = RansomwareActivityMonitor()

        warning = monitor.record_event(
            "moved",
            "/home/user/document.docx",
            "/home/user/document.docx.encrypted",
            now=100,
        )

        self.assertIn("extensão incomum", warning)

    def test_alerts_on_burst_of_distinct_file_changes(self):
        monitor = RansomwareActivityMonitor()
        warning = None

        for index in range(monitor.CHANGED_FILE_THRESHOLD):
            warning = monitor.record_event(
                "modified",
                f"/home/user/file-{index}.txt",
                now=100 + index / 10,
            )

        self.assertIn("Muitas alterações", warning)

    def test_does_not_repeat_behavior_alert_during_cooldown(self):
        monitor = RansomwareActivityMonitor()
        first_warning = monitor.record_event(
            "moved", "/tmp/a.txt", "/tmp/a.txt.locked", now=100
        )
        second_warning = monitor.record_event(
            "moved", "/tmp/b.txt", "/tmp/b.txt.locked", now=101
        )

        self.assertIsNotNone(first_warning)
        self.assertIsNone(second_warning)

    def test_discards_events_outside_the_detection_window(self):
        monitor = RansomwareActivityMonitor()

        for index in range(monitor.CHANGED_FILE_THRESHOLD - 1):
            monitor.record_event("modified", f"/tmp/old-{index}", now=100)

        warning = monitor.record_event("modified", "/tmp/current", now=116)

        self.assertIsNone(warning)


if __name__ == "__main__":
    unittest.main()
