import json
import ssl
import time
import traceback
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from aiohttp import web
from cryptography import x509

# ---------- Paths ----------
BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR / "out"
AUDIT_LOG_PATH = BASE_DIR / "audit.log"

SERVER_CERT = OUT_DIR / "server.crt"
SERVER_KEY = OUT_DIR / "server.key"
ROOT_CA_CERT = OUT_DIR / "rootCA.crt"

# ---------- Simple in-memory "device" state ----------
STATE = {
    "locked": True,
    "last_actor": None,
    "last_action": None,
    "last_time": None,
}

# ---------- Replay protection ----------
NONCES = defaultdict(lambda: deque(maxlen=200))
MAX_SKEW_SECONDS = 30


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now_utc().isoformat()


def parse_peer_cert_der(request: web.Request):
    """
    Extract the client certificate from the TLS transport and return it
    as a cryptography.x509.Certificate object. Return None if unavailable.
    """
    try:
        transport = request.transport
        if transport is None:
            return None

        ssl_object = transport.get_extra_info("ssl_object")
        if ssl_object is None:
            return None

        der = ssl_object.getpeercert(binary_form=True)
        if not der:
            return None

        return x509.load_der_x509_certificate(der)
    except Exception as e:
        print(f"[ERROR] parse_peer_cert_der failed: {e}")
        traceback.print_exc()
        return None


def get_cn(cert: x509.Certificate) -> str:
    try:
        attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else "unknown"
    except Exception:
        return "unknown"


def get_serial_hex(cert: x509.Certificate) -> str:
    try:
        return format(cert.serial_number, "X")
    except Exception:
        return "unknown"


def real_expired(cert: x509.Certificate) -> bool:
    """
    Handle cryptography version differences safely.
    Fail closed if validity cannot be evaluated.
    """
    try:
        if hasattr(cert, "not_valid_after_utc"):
            return cert.not_valid_after_utc < now_utc()

        nva = cert.not_valid_after
        if nva.tzinfo is None:
            nva = nva.replace(tzinfo=timezone.utc)
        return nva < now_utc()
    except Exception as e:
        print(f"[ERROR] certificate expiration check failed: {e}")
        traceback.print_exc()
        return True


def role_from_cn(cn: str) -> str:
    normalized = cn.lower().strip()
    if normalized in ("admin", "resident", "maintenance"):
        return normalized
    return "unknown"


def allowed(role: str, action: str) -> bool:
    if action == "status":
        return role in ("admin", "resident", "maintenance")
    if action == "lock":
        return role in ("admin", "resident", "maintenance")
    if action == "unlock":
        return role in ("admin", "resident")
    return False


def check_replay(cn: str, ts: str, nonce: str) -> bool:
    if not ts or not nonce:
        return False

    try:
        ts_value = int(ts)
    except ValueError:
        return False

    now_value = int(time.time())
    if abs(now_value - ts_value) > MAX_SKEW_SECONDS:
        return False

    key = f"{ts_value}:{nonce}"
    bucket = NONCES[cn]

    if key in bucket:
        return False

    bucket.append(key)
    return True


def action_name_from_request(request: web.Request) -> str:
    if request.path == "/api/status":
        return "status"
    if request.path == "/api/lock":
        return "lock"
    if request.path == "/api/unlock":
        return "unlock"
    return "unknown"


def get_source_ip(request: web.Request) -> str:
    transport = request.transport
    if transport is None:
        return "unknown"

    peer = transport.get_extra_info("peername")
    if isinstance(peer, tuple) and len(peer) >= 1:
        return str(peer[0])

    return "unknown"


def append_audit_log(
    request: web.Request,
    action: str,
    result: str,
    cert: x509.Certificate = None,
    role: str = None,
    cn: str = None,
) -> None:
    try:
        if cert is not None:
            cn = cn or get_cn(cert)

        if role is None and cn is not None:
            role = role_from_cn(cn)

        record = {
            "timestamp": now_iso(),
            "client_cn": cn or "unknown",
            "role": role or "unknown",
            "action": action,
            "result": result,
            "source_ip": get_source_ip(request),
            "nonce": request.headers.get("X-Nonce", ""),
            "certificate_serial_number": get_serial_hex(cert) if cert else "unknown",
        }

        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
    except Exception as e:
        print(f"[ERROR] audit logging failed: {e}")
        traceback.print_exc()


@web.middleware
async def authz_middleware(request: web.Request, handler):
    action = action_name_from_request(request)

    try:
        cert = parse_peer_cert_der(request)
        if cert is None:
            append_audit_log(
                request=request,
                action=action,
                result="denied_no_cert",
                cert=None,
                role="unknown",
                cn="unknown",
            )
            return web.json_response(
                {"error": "mTLS required: no client certificate presented"},
                status=401,
            )

        cn = get_cn(cert)
        role = role_from_cn(cn)

        request["client_cert"] = cert
        request["identity_cn"] = cn
        request["role"] = role

        simulate_expired = request.headers.get("X-Simulate-Expired", "false").lower() == "true"
        if simulate_expired:
            append_audit_log(
                request=request,
                action=action,
                result="expired_cert_simulated",
                cert=cert,
                role=role,
                cn=cn,
            )
            return web.json_response(
                {"error": "certificate expired (simulated)"},
                status=401,
            )

        if real_expired(cert):
            append_audit_log(
                request=request,
                action=action,
                result="expired_cert_real",
                cert=cert,
                role=role,
                cn=cn,
            )
            return web.json_response(
                {"error": "certificate expired (real check)"},
                status=401,
            )

        if request.path in ("/api/lock", "/api/unlock"):
            ts = request.headers.get("X-Timestamp", "")
            nonce = request.headers.get("X-Nonce", "")
            if not check_replay(cn, ts, nonce):
                append_audit_log(
                    request=request,
                    action=action,
                    result="replay_rejected",
                    cert=cert,
                    role=role,
                    cn=cn,
                )
                return web.json_response(
                    {"error": "replay / bad timestamp / missing nonce"},
                    status=401,
                )

        return await handler(request)

    except Exception as e:
        print(f"[SERVER ERROR] middleware failure: {e}")
        traceback.print_exc()
        append_audit_log(
            request=request,
            action=action,
            result="server_error",
            cert=None,
            role="unknown",
            cn="unknown",
        )
        return web.json_response(
            {"error": "internal server error", "detail": str(e)},
            status=500,
        )


async def api_status(request: web.Request):
    try:
        role = request["role"]
        cn = request["identity_cn"]
        cert = request["client_cert"]

        if not allowed(role, "status"):
            append_audit_log(
                request=request,
                action="status",
                result="denied",
                cert=cert,
                role=role,
                cn=cn,
            )
            return web.json_response({"error": "forbidden"}, status=403)

        append_audit_log(
            request=request,
            action="status",
            result="allowed",
            cert=cert,
            role=role,
            cn=cn,
        )

        return web.json_response(
            {
                "device": "smartlock-001",
                "locked": STATE["locked"],
                "last_actor": STATE["last_actor"],
                "last_action": STATE["last_action"],
                "last_time": STATE["last_time"],
                "your_role": role,
                "your_cn": cn,
            }
        )
    except Exception as e:
        print(f"[SERVER ERROR] api_status failed: {e}")
        traceback.print_exc()
        return web.json_response({"error": "internal server error", "detail": str(e)}, status=500)


async def api_lock(request: web.Request):
    try:
        role = request["role"]
        cn = request["identity_cn"]
        cert = request["client_cert"]

        if not allowed(role, "lock"):
            append_audit_log(
                request=request,
                action="lock",
                result="denied",
                cert=cert,
                role=role,
                cn=cn,
            )
            return web.json_response({"error": "forbidden"}, status=403)

        STATE["locked"] = True
        STATE["last_actor"] = cn
        STATE["last_action"] = "LOCK"
        STATE["last_time"] = now_iso()

        append_audit_log(
            request=request,
            action="lock",
            result="allowed",
            cert=cert,
            role=role,
            cn=cn,
        )

        return await api_status(request)
    except Exception as e:
        print(f"[SERVER ERROR] api_lock failed: {e}")
        traceback.print_exc()
        return web.json_response({"error": "internal server error", "detail": str(e)}, status=500)


async def api_unlock(request: web.Request):
    try:
        role = request["role"]
        cn = request["identity_cn"]
        cert = request["client_cert"]

        if not allowed(role, "unlock"):
            append_audit_log(
                request=request,
                action="unlock",
                result="denied",
                cert=cert,
                role=role,
                cn=cn,
            )
            return web.json_response(
                {"error": "forbidden (maintenance cannot unlock)"},
                status=403,
            )

        STATE["locked"] = False
        STATE["last_actor"] = cn
        STATE["last_action"] = "UNLOCK"
        STATE["last_time"] = now_iso()

        append_audit_log(
            request=request,
            action="unlock",
            result="allowed",
            cert=cert,
            role=role,
            cn=cn,
        )

        return await api_status(request)
    except Exception as e:
        print(f"[SERVER ERROR] api_unlock failed: {e}")
        traceback.print_exc()
        return web.json_response({"error": "internal server error", "detail": str(e)}, status=500)


def build_ssl_context():
    missing = [p for p in (SERVER_CERT, SERVER_KEY, ROOT_CA_CERT) if not p.exists()]
    if missing:
        raise FileNotFoundError(
            "Missing TLS file(s): " + ", ".join(str(p) for p in missing)
        )

    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(str(SERVER_CERT), str(SERVER_KEY))
    ssl_ctx.load_verify_locations(cafile=str(ROOT_CA_CERT))
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ssl_ctx


def main():
    app = web.Application(middlewares=[authz_middleware])
    app.router.add_get("/api/status", api_status)
    app.router.add_post("/api/lock", api_lock)
    app.router.add_post("/api/unlock", api_unlock)

    ssl_ctx = build_ssl_context()
    web.run_app(app, host="127.0.0.1", port=8443, ssl_context=ssl_ctx)


if __name__ == "__main__":
    main()
