# services/vtu_service.py
"""
VTU.ng helper for server-side usage.

Usage:
    from services.vtu_service import VTUService
    vtu = VTUService()   # reads VTU_EMAIL & VTU_PASSWORD from env by default
    r = vtu.verify_customer("bet9ja", "8167542829")
    r = vtu.fund_betting("bet9ja", "8167542829", 1000)

Notes:
- Keep VTU credentials in environment variables: VTU_EMAIL, VTU_PASSWORD.
- This module does NOT load .env automatically (so you won't hit ModuleNotFoundError for python-dotenv).
  If you want local .env support, either set env vars or install python-dotenv and load it from your app entry.
"""
from __future__ import annotations
import os
import time
import logging
from typing import Optional, Tuple
import requests

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

class VTUService:
    BASE = "https://vtu.ng/wp-json/api/v1"
    TOKEN_TTL_DEFAULT = 3600  # seconds

    def __init__(self, email: Optional[str] = None, password: Optional[str] = None):
        """
        Initialize the VTU helper. By default reads VTU_EMAIL and VTU_PASSWORD from env.
        """
        self.email = email or os.getenv("VTU_EMAIL")
        self.password = password or os.getenv("VTU_PASSWORD")
        if not (self.email and self.password):
            raise RuntimeError("VTU_EMAIL and VTU_PASSWORD must be set in environment or passed to VTUService()")

        self._token: Optional[str] = None
        self._token_expires_at: int = 0

    # --------------------
    # Token management
    # --------------------
    def _fetch_token(self) -> str:
        """
        Obtain a fresh token from VTU authenticate endpoint.
        Raises requests.RequestException or RuntimeError on failure.
        """
        url = f"{self.BASE}/authenticate"
        payload = {"email": self.email, "password": self.password}
        logger.debug("VTU: requesting token from %s", url)

        r = requests.post(url, json=payload, timeout=12)
        r.raise_for_status()
        body = r.json() if r.text else {}

        # Try multiple common key shapes
        token = None
        ttl = self.TOKEN_TTL_DEFAULT
        if isinstance(body, dict):
            # common keys: token, access_token, data.token, data.access_token
            token = body.get("token") or body.get("access_token") or (body.get("data") or {}).get("token") or (body.get("data") or {}).get("access_token")
            # expiry keys
            ttl_val = body.get("expires_in") or body.get("ttl") or body.get("expires") or body.get("data", {}).get("expires_in")
            try:
                if ttl_val:
                    ttl = int(ttl_val)
            except Exception:
                ttl = self.TOKEN_TTL_DEFAULT

        if not token:
            raise RuntimeError(f"VTU token not found in auth response: {body}")

        # set cache expiry a little earlier than TTL
        self._token = token
        self._token_expires_at = int(time.time()) + max(30, ttl - 60)
        logger.info("VTU: obtained token (preview=%s), expires_in=%s", (token[:8] + "..."), ttl)
        return token

    def _ensure_token(self) -> str:
        """
        Return a valid token, refreshing if necessary.
        """
        if self._token and time.time() < self._token_expires_at:
            return self._token
        return self._fetch_token()

    def _headers(self) -> dict:
        token = self._ensure_token()
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # --------------------
    # Public API calls
    # --------------------
    def verify_customer(self, service_id: str, account: str, timeout: int = 12) -> requests.Response:
        """
        Verify a customer's betting account via VTU.
        Returns the requests.Response object (caller will inspect status_code and json/text).
        Attempts a few likely endpoint paths.
        """
        payload = {"service_id": service_id, "account": account}
        urls = [
            f"{self.BASE}/verify-customer",
            f"{self.BASE}/verify",
            f"{self.BASE}/verifycustomer",
        ]
        last_exc = None
        headers = self._headers()
        for url in urls:
            try:
                r = requests.post(url, json=payload, headers=headers, timeout=timeout)
                return r
            except requests.RequestException as e:
                last_exc = e
                logger.debug("VTU verify attempt failed %s: %s", url, e)
                # try next
                continue
        # if all attempts failed, raise last exception
        if last_exc:
            raise last_exc
        # fallback - shouldn't happen
        raise RuntimeError("Unable to call VTU verify endpoint")

    def fund_betting(self, service_id: str, account: str, amount: int, metadata: Optional[dict] = None, timeout: int = 15) -> requests.Response:
        """
        Fund a betting account.
        - amount should be integer (Naira).
        - metadata is optional and included in the payload if provided.
        Returns requests.Response (caller inspects status_code and json/text).
        """
        payload = {"service_id": service_id, "account": account, "amount": str(int(amount))}
        if metadata:
            payload["metadata"] = metadata

        urls = [
            f"{self.BASE}/fund-betting",
            f"{self.BASE}/betting",
            f"{self.BASE}/fund",
            f"{self.BASE}/topup",
        ]
        last_exc = None
        headers = self._headers()
        for url in urls:
            try:
                r = requests.post(url, json=payload, headers=headers, timeout=timeout)
                return r
            except requests.RequestException as e:
                last_exc = e
                logger.debug("VTU fund attempt failed %s: %s", url, e)
                continue
        if last_exc:
            raise last_exc
        raise RuntimeError("Unable to call VTU fund endpoint")

    # --------------------
    # Optional helpers
    # --------------------
    def get_wallet_balance(self, timeout: int = 10) -> Tuple[Optional[requests.Response], Optional[str]]:
        """
        Call wallet-balance endpoint; returns (response, None) on success or (None, error_str).
        """
        try:
            headers = self._headers()
            url = f"{self.BASE}/wallet-balance"
            r = requests.get(url, headers=headers, timeout=timeout)
            return r, None
        except Exception as e:
            return None, str(e)