import os
import unittest
import subprocess
from mock_lapi import MockLAPI
from time import sleep

import requests

NGINX_PORT = 51140


class TestNGINX(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(["docker", "compose", "build"])

    def setUp(self) -> None:
        self.lapi = MockLAPI()
        self.lapi.start()
        self.nginx_process = subprocess.Popen(
            ["docker", "compose", "up"],
        )
        sleep(5)
        return super().setUp()

    def assertNotBanned(self):
        response = requests.get(f"http://localhost:{NGINX_PORT}")
        self.assertEqual(response.status_code, 200)

    def assertBanned(self):
        response = requests.get(f"http://localhost:{NGINX_PORT}")
        self.assertEqual(response.status_code, 403)

    def tearDown(self):
        self.lapi.stop()
        subprocess.run(["docker", "compose", "down"])
        self.nginx_process.kill()
        self.nginx_process.wait()

    def test_ip_ban_unban(self):
        self.assertNotBanned()
        self.lapi.ds.insert_decisions(
            [
                {
                    "id": "1",
                    "origin": "cscli",
                    "type": "ban",
                    "value": "127.0.0.1",
                    "duration": "1h",
                    "scope": "ip",
                }
            ]
        )
        sleep(5)
        self.assertBanned()
        self.lapi.ds.delete_decisions_by_ip("127.0.0.1")
        sleep(5)
        self.assertNotBanned()

    def test_ip_range_ban_unban(self):
        self.assertNotBanned()
        self.lapi.ds.insert_decisions(
            [
                {
                    "id": "1",
                    "origin": "cscli",
                    "type": "ban",
                    "value": "127.0.0.0/24",
                    "duration": "1h",
                    "scope": "range",
                }
            ]
        )
        sleep(5)
        self.assertBanned()

    def test_country_ban_unban(self):
        self.assertNotBanned()
        self.lapi.ds.insert_decisions(
            [
                {
                    "id": "1",
                    "origin": "cscli",
                    "type": "ban",
                    "value": "US",
                    "duration": "1h",
                    "scope": "country",
                }
            ]
        )
        sleep(5)
        self.assertBanned()

    def test_as_ban_unban(self):
        self.assertNotBanned()
        self.lapi.ds.insert_decisions(
            [
                {
                    "id": "1",
                    "origin": "cscli",
                    "type": "ban",
                    "value": "12300",
                    "duration": "1h",
                    "scope": "AS",
                }
            ]
        )
        sleep(5)
        self.assertBanned()
