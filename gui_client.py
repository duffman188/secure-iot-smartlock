import json
import secrets
import time
import tkinter as tk
from tkinter import messagebox, ttk

import requests

BASE_URL = "https://127.0.0.1:8443"
CA_FILE = "pki/out/rootCA.crt"

CLIENTS = {
    "admin": ("pki/out/admin.crt", "pki/out/admin.key"),
    "resident": ("pki/out/resident.crt", "pki/out/resident.key"),
    "maintenance": ("pki/out/maintenance.crt", "pki/out/maintenance.key"),
}


def headers(sim_expired: bool, include_replay: bool) -> dict:
    """
    Build HTTP headers for expiration simulation and replay protection.
    """
    request_headers = {
        "X-Simulate-Expired": "true" if sim_expired else "false"
    }

    if include_replay:
        request_headers["X-Timestamp"] = str(int(time.time()))
        request_headers["X-Nonce"] = secrets.token_hex(8)

    return request_headers


def json_pretty(data) -> str:
    """
    Convert a Python object to pretty JSON text.
    """
    return json.dumps(data, indent=2)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Smart Lock IoT Simulator (HTTPS + mTLS)")
        self.geometry("520x320")
        self.resizable(False, False)

        self.role = tk.StringVar(value="resident")
        self.sim_expired = tk.BooleanVar(value=False)

        top = ttk.Frame(self, padding=12)
        top.pack(fill="both", expand=True)

        ttk.Label(top, text="Client role (certificate CN):").grid(
            row=0, column=0, sticky="w"
        )

        role_box = ttk.Combobox(
            top,
            textvariable=self.role,
            values=list(CLIENTS.keys()),
            state="readonly",
            width=18,
        )
        role_box.grid(row=0, column=1, sticky="w", padx=(8, 0))

        ttk.Checkbutton(
            top,
            text="Simulate expired cert",
            variable=self.sim_expired,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))

        btns = ttk.Frame(top)
        btns.grid(row=2, column=0, columnspan=2, sticky="w", pady=(14, 0))

        ttk.Button(btns, text="Get Status", command=self.get_status).grid(
            row=0, column=0, padx=(0, 8)
        )
        ttk.Button(btns, text="LOCK", command=self.do_lock).grid(
            row=0, column=1, padx=(0, 8)
        )
        ttk.Button(btns, text="UNLOCK", command=self.do_unlock).grid(
            row=0, column=2
        )

        ttk.Separator(top).grid(row=3, column=0, columnspan=2, sticky="ew", pady=14)

        self.status_lbl = ttk.Label(
            top,
            text="Status: (click Get Status)",
            font=("Helvetica", 12),
        )
        self.status_lbl.grid(row=4, column=0, columnspan=2, sticky="w")

        self.detail = tk.Text(top, height=8, width=60)
        self.detail.grid(row=5, column=0, columnspan=2, sticky="w", pady=(10, 0))
        self.detail.configure(state="disabled")

        for i in range(2):
            top.columnconfigure(i, weight=1)

    def client_cert(self):
        """
        Return the certificate and private key pair for the selected role.
        """
        role = self.role.get().strip().lower()
        return CLIENTS[role]

    def show(self, text: str) -> None:
        """
        Replace the lower text box content.
        """
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", text)
        self.detail.configure(state="disabled")

    def request(self, method: str, path: str, include_replay: bool = False):
        """
        Send an HTTPS request using mTLS.
        Return a requests.Response object on HTTP success or HTTP error.
        Return None only for transport-level failures.
        """
        cert = self.client_cert()

        try:
            response = requests.request(
                method=method,
                url=f"{BASE_URL}{path}",
                cert=cert,
                verify=CA_FILE,
                headers=headers(self.sim_expired.get(), include_replay),
                timeout=5,
            )
            return response
        except requests.exceptions.SSLError as exc:
            error_payload = {"error": f"TLS Error: {str(exc)}"}
            self.show(json_pretty(error_payload))
            self.status_lbl.configure(text="Status: TLS ERROR")
            messagebox.showerror("TLS Error", str(exc))
        except requests.exceptions.RequestException as exc:
            error_payload = {"error": f"Network Error: {str(exc)}"}
            self.show(json_pretty(error_payload))
            self.status_lbl.configure(text="Status: NETWORK ERROR")
            messagebox.showerror("Network Error", str(exc))

        return None

    def refresh_from_status(self, data: dict) -> None:
        """
        Update the top status line and lower details box using a successful status payload.
        """
        locked = data.get("locked")
        role = data.get("your_role", "unknown")
        cn = data.get("your_cn", "unknown")

        if locked is True:
            state = "LOCKED 🔒"
        elif locked is False:
            state = "UNLOCKED 🔓"
        else:
            state = "UNKNOWN"

        self.status_lbl.configure(text=f"Status: {state}  |  You: {role} ({cn})")
        self.show(json_pretty(data))

    def handle_response(self, response) -> None:
        """
        Handle both success and error responses and always show
        the response body in the lower text box.
        """
        try:
            data = response.json()
            body_text = json_pretty(data)
        except ValueError:
            data = None
            body_text = response.text if response.text else f"HTTP {response.status_code}"

        self.show(body_text)

        if response.status_code == 200 and isinstance(data, dict):
            self.refresh_from_status(data)
            return

        error_message = ""
        if isinstance(data, dict):
            error_message = data.get("error", "")

        if error_message:
            self.status_lbl.configure(
                text=f"Status: ERROR ({response.status_code}) - {error_message}"
            )
        else:
            self.status_lbl.configure(text=f"Status: ERROR ({response.status_code})")

    def get_status(self) -> None:
        """
        Request the current lock state.
        """
        response = self.request("GET", "/api/status", include_replay=False)
        if response is None:
            return
        self.handle_response(response)

    def do_lock(self) -> None:
        """
        Send a lock request.
        """
        response = self.request("POST", "/api/lock", include_replay=True)
        if response is None:
            return
        self.handle_response(response)

    def do_unlock(self) -> None:
        """
        Send an unlock request.
        """
        response = self.request("POST", "/api/unlock", include_replay=True)
        if response is None:
            return
        self.handle_response(response)


if __name__ == "__main__":
    App().mainloop()
