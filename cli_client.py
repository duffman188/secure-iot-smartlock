import argparse
import json
import secrets
import sys
import time

import requests

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8443
CA_FILE = "pki/out/rootCA.crt"

CLIENTS = {
    "admin": ("pki/out/admin.crt", "pki/out/admin.key"),
    "resident": ("pki/out/resident.crt", "pki/out/resident.key"),
    "maintenance": ("pki/out/maintenance.crt", "pki/out/maintenance.key"),
}


def build_headers(simulate_expired: bool, include_replay_headers: bool) -> dict:
    """
    Build HTTP headers used by the server for expiration simulation
    and replay protection fields.
    """
    headers = {
        "X-Simulate-Expired": "true" if simulate_expired else "false",
    }

    if include_replay_headers:
        headers["X-Timestamp"] = str(int(time.time()))
        headers["X-Nonce"] = secrets.token_hex(8)

    return headers


def perform_request(
    base_url: str,
    role: str,
    action: str,
    simulate_expired: bool,
    timeout: int,
) -> requests.Response:
    """
    Send a request to the secure API using the certificate mapped to the selected role.
    """
    if role not in CLIENTS:
        raise ValueError(f"Unsupported role: {role}")

    cert_pair = CLIENTS[role]

    if action == "status":
        method = "GET"
        path = "/api/status"
        include_replay_headers = False
    elif action == "lock":
        method = "POST"
        path = "/api/lock"
        include_replay_headers = True
    elif action == "unlock":
        method = "POST"
        path = "/api/unlock"
        include_replay_headers = True
    else:
        raise ValueError(f"Unsupported action: {action}")

    response = requests.request(
        method=method,
        url=f"{base_url}{path}",
        cert=cert_pair,
        verify=CA_FILE,
        headers=build_headers(simulate_expired, include_replay_headers),
        timeout=timeout,
    )
    return response


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Command-line client for the Secure IoT Smart Lock API."
    )
    parser.add_argument(
        "action",
        choices=["status", "lock", "unlock"],
        help="Action to send to the server.",
    )
    parser.add_argument(
        "--role",
        choices=["admin", "resident", "maintenance"],
        default="resident",
        help="Client role / certificate CN to use.",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help="API server host (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="API server port (default: 8443).",
    )
    parser.add_argument(
        "--simulate-expired",
        action="store_true",
        help="Ask the server to simulate certificate expiration rejection.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Network timeout in seconds.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_url = f"https://{args.host}:{args.port}"

    try:
        response = perform_request(
            base_url=base_url,
            role=args.role,
            action=args.action,
            simulate_expired=args.simulate_expired,
            timeout=args.timeout,
        )
    except requests.exceptions.SSLError as exc:
        print(f"TLS error: {exc}", file=sys.stderr)
        return 2
    except requests.exceptions.RequestException as exc:
        print(f"Network error: {exc}", file=sys.stderr)
        return 3
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 4

    print(f"HTTP {response.status_code}")

    try:
        payload = response.json()
        print(json.dumps(payload, indent=2))
    except ValueError:
        print(response.text)

    return 0 if response.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())