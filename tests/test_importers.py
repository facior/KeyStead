"""
Testy jednostkowe importerów: Bitwarden, KeePass, 1Password, LastPass i Browser.
"""

import json
import os
import tempfile
import unittest
import zipfile
from importers import run_import, detect_importer


class TestImporters(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        for f in os.listdir(self.temp_dir):
            os.remove(os.path.join(self.temp_dir, f))
        os.rmdir(self.temp_dir)

    def test_bitwarden_json_import(self):
        bw_data = {
            "encrypted": False,
            "folders": [{"id": "f1", "name": "Praca"}],
            "items": [
                {
                    "name": "Konto Slack",
                    "type": 1,
                    "folderId": "f1",
                    "login": {
                        "username": "jan@firma.pl",
                        "password": "SlackPassword123!",
                        "uris": [{"uri": "https://slack.com"}],
                        "totp": "JBSWY3DPEHPK3PXP"
                    },
                    "notes": "Notatka firmowa",
                    "favorite": True
                },
                {
                    "name": "Karta Firmowa",
                    "type": 3,
                    "card": {
                        "cardholderName": "Jan Kowalski",
                        "number": "4111111111111111",
                        "expMonth": "12",
                        "expYear": "2028",
                        "code": "123"
                    }
                }
            ]
        }
        file_path = os.path.join(self.temp_dir, "bitwarden_test.json")
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(bw_data, f)

        res = run_import(file_path)
        self.assertTrue(res.success)
        self.assertEqual(len(res.items), 2)

        slack = res.items[0]
        self.assertEqual(slack.title, "Konto Slack")
        self.assertEqual(slack.username, "jan@firma.pl")
        self.assertEqual(slack.category, "Praca")
        self.assertEqual(slack.totp_secret, "JBSWY3DPEHPK3PXP")
        self.assertTrue(slack.favorite)

        card = res.items[1]
        self.assertEqual(card.title, "Karta Firmowa")
        self.assertEqual(card.category, "Karty płatnicze")
        self.assertEqual(card.custom_fields.get("Numer karty"), "4111111111111111")

    def test_bitwarden_csv_import(self):
        csv_content = (
            "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
            "Osobiste,1,1,GitHub,Moje repozytoria,,0,https://github.com,octocat,Secr3tToken!,otpauth://totp/GitHub:octocat?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ\n"
        )
        file_path = os.path.join(self.temp_dir, "bitwarden_test.csv")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(csv_content)

        res = run_import(file_path)
        self.assertTrue(res.success)
        self.assertEqual(len(res.items), 1)
        item = res.items[0]
        self.assertEqual(item.title, "GitHub")
        self.assertEqual(item.username, "octocat")
        self.assertEqual(item.category, "Osobiste")
        self.assertEqual(item.totp_secret, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
        self.assertTrue(item.favorite)

    def test_lastpass_csv_import(self):
        csv_content = (
            "url,username,password,totp,extra,name,grouping,fav\n"
            "https://netflix.com,user@netflix.com,MyPass123,,Konto rodzinne,Netflix,Rozrywka,1\n"
        )
        file_path = os.path.join(self.temp_dir, "lastpass_test.csv")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(csv_content)

        res = run_import(file_path)
        self.assertTrue(res.success)
        self.assertEqual(len(res.items), 1)
        item = res.items[0]
        self.assertEqual(item.title, "Netflix")
        self.assertEqual(item.username, "user@netflix.com")
        self.assertEqual(item.category, "Rozrywka")
        self.assertTrue(item.favorite)

    def test_onepassword_1pux_import(self):
        onepux_data = {
            "accounts": [{
                "vaults": [{
                    "items": [{
                        "categoryUuid": "001",
                        "overview": {
                            "title": "Amazon",
                            "url": "https://amazon.com",
                            "tags": ["zakupy"]
                        },
                        "details": {
                            "notesPlain": "Darmowa dostawa Prime",
                            "fields": [
                                {"designation": "username", "value": "buyer@amazon.com"},
                                {"designation": "password", "value": "AmazonPass999!"}
                            ]
                        }
                    }]
                }]
            }]
        }
        file_path = os.path.join(self.temp_dir, "export.1pux")
        with zipfile.ZipFile(file_path, "w") as z:
            z.writestr("export.data", json.dumps(onepux_data))

        res = run_import(file_path)
        self.assertTrue(res.success)
        self.assertEqual(len(res.items), 1)
        item = res.items[0]
        self.assertEqual(item.title, "Amazon")
        self.assertEqual(item.username, "buyer@amazon.com")
        self.assertEqual(item.password, "AmazonPass999!")
        self.assertEqual(item.tags, ["zakupy"])


if __name__ == "__main__":
    unittest.main()
