# betting.py
"""
Betting blueprint + VTU health check route.

Drop this file into the same folder as app.py (backend-flask/betting.py).
If your app registers the blueprint with url_prefix="/api" then the
health route will be available at: GET /api/_check_vtu
"""
import os
import math
import traceback
from flask import Blueprint, request, jsonify, current_app

# Try importing your VTU wrapper. Capture import error so it can be surfaced.
VTUService = None
_VTU_IMPORT_ERROR = None
try:
    from services.vtu_service import VTUService  # expected path: backend-flask/services/vtu_service.py
except Exception as e:
    VTUService = None
    _VTU_IMPORT_ERROR = str(e)

betting_bp = Blueprint("betting_bp", __name__)

# Simple built-in list of betting platforms (slug == VTU service_id)
DEFAULT_BETTING_SITES = [
    {"name": "iLotBet", "slug": "ilotbet", "color": "#00897b"},
    {"name": "Bet9ja", "slug": "bet9ja", "color": "#1b9e5a"},
    {"name": "SportyBet", "slug": "sportybet", "color": "#e53935"},
    {"name": "BetKing", "slug": "betking", "color": "#1e3a8a"},
    {"name": "MSport", "slug": "msport", "color": "#ff9800"},
    {"name": "1XBet", "slug": "1xbet", "color": "#0057b7"},
    {"name": "Betano", "slug": "betano", "color": "#ff6b37"},
    {"name": "Betway", "slug": "betway", "color": "#111111"},
    {"name": "Melbet", "slug": "melbet", "color": "#111111"},
    {"name": "BangBet", "slug": "bangbet", "color": "#ffd600"},
    {"name": "BetCorrect", "slug": "betcorrect", "color": "#2a6b2f"},
    {"name": "NaijaBet", "slug": "naijabet", "color": "#e21b1b"},
    {"name": "Betgr8", "slug": "betgr8", "color": "#1f8fff"},
    {"name": "Wazobet", "slug": "wazobet", "color": "#12b76a"},
]

# Option: if you want the server to reveal charged_amount (for testing), set env SHOW_CHARGE=true
SHOW_CHARGE = os.getenv("SHOW_CHARGE", "false").lower() in ("1", "true", "yes")

# Lazy VTU service instance (will be created on first request)
_vtu_instance = None


def get_vtu():
    """
    Return tuple (vtu_instance_or_None, error_or_None).
    If VTUService import failed, returns import error message.
    If VTUService init failed (missing env, etc.) returns that message.
    """
    global _vtu_instance
    if _vtu_instance is None:
        if VTUService is None:
            if _VTU_IMPORT_ERROR:
                return None, f"VTUService import failed: {_VTU_IMPORT_ERROR}"
            return None, "VTUService (services.vtu_service) not available/importable"
        try:
            _vtu_instance = VTUService()
        except Exception as e:
            # return initialization error (e.g. missing VTU_EMAIL/VTU_PASSWORD)
            return None, f"failed to initialize VTUService: {e}"
    return _vtu_instance, None


def secret_apply_fee(nominal):
    """Deduct 1% (secret). Rounds to nearest integer."""
    return round(nominal * 99 / 100)


# -------------------------
# Health / debug route (blueprint)
# -------------------------
@betting_bp.route("/_check_vtu", methods=["GET"])
def _check_vtu():
    """
    Health check for VTU integration. Returns stage and details:
      - stage: import  -> services.vtu_service import failed
      - stage: init    -> VTUService() initialization failed (likely missing env)
      - stage: token   -> token fetch failed (auth/network)
      - stage: ok      -> token obtained successfully

    This endpoint is safe: it does NOT expose secrets, only error messages.
    """
    # 1) import stage
    if VTUService is None:
        # If import failed earlier, return that detail
        detail = _VTU_IMPORT_ERROR or "VTUService not importable"
        return jsonify({"status": "error", "stage": "import", "details": detail}), 500

    # 2) init stage
    try:
        vtu, err = get_vtu()
        if err:
            return jsonify({"status": "error", "stage": "init", "details": err}), 500
    except Exception as e:
        # unexpected
        current_app.logger.exception("vtu init unexpected")
        return jsonify({"status": "error", "stage": "init", "details": str(e)}), 500

    # 3) token stage
    try:
        token = vtu._ensure_token()
    except Exception as e:
        current_app.logger.exception("vtu token fetch failed")
        return jsonify({"status": "error", "stage": "token", "details": str(e)}), 500

    # success
    return jsonify({"status": "success", "stage": "ok", "token_preview": (token[:12] + "...") if token else None}), 200


# -------------------------
# Routes
# -------------------------
@betting_bp.route("/betting-sites", methods=["GET"])
def betting_sites():
    """
    Return list of supported betting sites for the frontend.
    """
    try:
        return jsonify({"status": "success", "sites": DEFAULT_BETTING_SITES}), 200
    except Exception as e:
        current_app.logger.exception("betting_sites error")
        return jsonify({"status": "error", "message": "Internal server error", "details": str(e)}), 500


@betting_bp.route("/verify-betting", methods=["POST"])
def verify_betting():
    """
    Verify a betting account via VTU.ng.
    Body: { "service_id": "bet9ja", "account": "8167542829" }
    Returns: JSON with provider response and normalized customer_name when available.
    """
    try:
        payload = request.get_json(silent=True) or {}
        service_id = (payload.get("service_id") or "").strip()
        account = (payload.get("account") or "").strip()

        if not service_id or not account:
            return jsonify({"status": "error", "message": "service_id and account are required"}), 400

        vtu, err = get_vtu()
        if err:
            # surface helpful details to logs and response (safe)
            current_app.logger.error("VTU not configured: %s", err)
            return jsonify({"status": "error", "message": "VTU not configured", "details": err}), 500

        # call VTU verify; VTUService.verify_customer should return requests.Response
        res = vtu.verify_customer(service_id, account)
        # try parse json body
        try:
            body = res.json()
        except Exception:
            body = {"raw_text": res.text}

        if res.status_code >= 400:
            return jsonify({
                "status": "error",
                "message": "Provider verification failed",
                "provider_status": res.status_code,
                "provider_response": body
            }), 400

        # try to pick out customer name from common keys
        customer_name = None
        if isinstance(body, dict):
            customer_name = (
                (body.get("customer") or {}).get("name")
                or (body.get("data") or {}).get("customer_name")
                or (body.get("data") or {}).get("name")
                or body.get("name")
                or body.get("customer")
            )

        return jsonify({
            "status": "success",
            "service_id": service_id,
            "account": account,
            "customer_name": customer_name,
            "provider_response": body
        }), 200

    except Exception as e:
        current_app.logger.exception("verify_betting error")
        return jsonify({"status": "error", "message": "Internal server error", "details": str(e)}), 500


@betting_bp.route("/fund-betting", methods=["POST"])
def fund_betting():
    """
    Fund a betting account via VTU.ng.
    Body: { "service_id": "bet9ja", "account": "8167542829", "nominal_amount": 1000 }
    Server:
      - validates inputs
      - enforces nominal >= 100
      - secretly deducts 1% and calls VTU with the reduced amount
      - returns provider response (does NOT reveal charged_amount unless SHOW_CHARGE env true)
    """
    try:
        payload = request.get_json(silent=True) or {}
        service_id = (payload.get("service_id") or "").strip()
        account = (payload.get("account") or "").strip()
        nominal = payload.get("nominal_amount")

        if not service_id or not account:
            return jsonify({"status": "error", "message": "service_id and account are required"}), 400

        try:
            nominal = int(nominal)
        except Exception:
            return jsonify({"status": "error", "message": "nominal_amount must be an integer"}), 400

        if nominal < 100:
            return jsonify({"status": "error", "message": "Minimum amount is 100 Naira"}), 400

        charged = secret_apply_fee(nominal)

        vtu, err = get_vtu()
        if err:
            current_app.logger.error("VTU not configured: %s", err)
            return jsonify({"status": "error", "message": "VTU not configured", "details": err}), 500

        # metadata can include who initiated, reference id, etc. You can also store transaction in DB here.
        meta = payload.get("metadata") or {}
        meta.update({"origin": "PayMe"})

        res = vtu.fund_betting(service_id, account, charged, metadata=meta)
        try:
            body = res.json()
        except Exception:
            body = {"raw_text": res.text}

        if res.status_code >= 400:
            return jsonify({
                "status": "error",
                "message": "Provider fund failed",
                "provider_status": res.status_code,
                "provider_response": body
            }), 400

        response_payload = {
            "status": "success",
            "service_id": service_id,
            "account": account,
            "nominal_amount": nominal,
            "provider_response": body
        }
        # only include charged_amount if explicit testing flag set
        if SHOW_CHARGE:
            response_payload["charged_amount"] = charged

        return jsonify(response_payload), 200

    except Exception as e:
        current_app.logger.exception("fund_betting error")
        return jsonify({"status": "error", "message": "Internal server error", "details": str(e)}), 500
```0