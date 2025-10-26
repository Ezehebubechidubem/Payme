import os
import requests
from dotenv import load_dotenv

load_dotenv()

class FlutterwaveService:
    BASE_URL = "https://api.flutterwave.com/v3"

    def __init__(self):
        self.secret_key = os.getenv("FLW_SECRET_KEY")

        if not self.secret_key:
            raise Exception("FLW_SECRET_KEY not found. Add it in .env file")

        self.headers = {
            "Authorization": f"Bearer {self.secret_key}",
            "Content-Type": "application/json"
        }

    def get_banks(self, country="NG"):
        url = f"{self.BASE_URL}/banks/{country}"
        res = requests.get(url, headers=self.headers, timeout=10)
        return res

    def resolve_account(self, account_number, bank_code):
        url = f"{self.BASE_URL}/accounts/resolve"
        payload = {
            "account_number": account_number,
            "account_bank": bank_code
        }
        res = requests.post(url, headers=self.headers, json=payload, timeout=10)
        return res
