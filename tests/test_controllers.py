import subprocess
import unittest
from app import controllers, models


class LinuxControllersTestCase(unittest.TestCase):
    def test_daemon_status_unknown(self):
        subprocess.check_output(f"systemctl stop suricata", shell=True)
        self.assertEqual('Unknown', controllers.get_daemon_status())

    def test_daemon_status_active(self):
        subprocess.check_output(f"systemctl start suricata", shell=True)
        self.assertIn('active', controllers.get_daemon_status())

    def test_last_stats(self):
        error, data = controllers.get_last_stats()
        self.assertEqual(0, error)

    def test_alerts(self):
        error, data, pages = controllers.get_alerts(1)
        self.assertEqual(0, error)

    def test_page_count(self):
        error, data, pages = controllers.get_alerts(1)
        real_pages = models.Alert.count() // 50 + 1
        self.assertEqual(real_pages, pages)

    def test_suricata_log(self):
        self.assertTrue(controllers.get_suricata_log())


if __name__ == '__main__':
    unittest.main()
