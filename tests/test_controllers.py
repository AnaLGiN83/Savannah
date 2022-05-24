import os
import subprocess
import tempfile
import time
import unittest
from app import controllers, models, config
from test_models import with_test_db


class LinuxControllersTestCase(unittest.TestCase):
    def test_daemon_status_unknown(self):
        subprocess.check_output(f"systemctl stop suricata", shell=True)
        time.sleep(5)
        self.assertIn('inactive', controllers.get_daemon_status())

    def test_daemon_status_active(self):
        subprocess.check_output(f"systemctl start suricata", shell=True)
        time.sleep(60)
        self.assertIn('active', controllers.get_daemon_status())

    def test_suricata_log(self):
        self.assertTrue(controllers.get_suricata_log())


class LogsControllersTestCase(unittest.TestCase):
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


@with_test_db((models.User,))
class UsersControllersTestCase(unittest.TestCase):
    def test_create_user(self):
        self.assertEqual(0, controllers.create_user('test', 'test', False))
        self.assertTrue(models.User.get(models.User.username == 'test'))

    def test_create_exists_user(self):
        self.assertEqual(0, controllers.create_user('test', 'test', False))
        self.assertEqual(3, controllers.create_user('test', 'test', False))

    def test_delete_user_by_id(self):
        self.assertEqual(0, controllers.create_user('test', 'test', False))
        id = models.User.get(models.User.username == 'test')
        self.assertEqual(0, controllers.delete_user_by_id(id))
        try:
            models.User.get(models.User.username == 'test')
        except models.DoesNotExist:
            self.assertTrue(True)
        else:
            self.assertFalse(False)

    def test_delete_not_exists_user(self):
        self.assertEqual(0, controllers.create_user('test', 'test', False))
        self.assertEqual(1, controllers.delete_user_by_id(100))

    def test_admin_user_by_id(self):
        self.assertEqual(0, controllers.create_user('test', 'test', False))
        id = models.User.get(models.User.username == 'test')
        self.assertEqual(0, controllers.set_user_admin_by_id(id, True))
        self.assertTrue(models.User.get(models.User.username == 'test').is_admin)

    def test_admin_not_exists_user(self):
        self.assertEqual(0, controllers.create_user('test', 'test', False))
        self.assertEqual(1, controllers.set_user_admin_by_id(100, True))

if __name__ == '__main__':
    unittest.main()
