import tkinter as tk
from tkinter import ttk, messagebox
import requests
import time
import secrets

BASE_URL = "https://127.0.0.1:8443"
CA_FILE = "pki/out/rootCA.crt"

CLIENTS = {
    "admin": ("pki/out/admin.crt", "pki/out/admin.key"),
    "resident": ("pki/out/resident.crt", "pki/out/resident.key"),
    "maintenance": ("pki/out/maintenance.crt", "pki/out/maintenance.key"),
}

def headers(sim_expired: bool, include_replay: bool):
    h = {"X-Simulate-Expired": "true" if sim_expired else "false"}
    if include_replay:
        h["X-Timestamp"] = str(int(time.time()))
        h["X-Nonce"] = secrets.token_hex(8)
    return h

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

        # Role selector
        ttk.Label(top, text="Client role (certificate CN):").grid(row=0, column=0, sticky="w")
        role_box = ttk.Combobox(top, textvariable=self.role, values=list(CLIENTS.keys()), state="readonly", width=18)
        role_box.grid(row=0, column=1, sticky="w", padx=(8, 0))

        # Expired simulation checkbox
        ttk.Checkbutton(top, text="Simulate expired cert", variable=self.sim_expired).grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))

        # Buttons
        btns = ttk.Frame(top)
        btns.grid(row=2, column=0, columnspan=2, sticky="w", pady=(14, 0))

        ttk.Button(btns, text="Get Status", command=self.get_status).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(btns, text="LOCK", command=self.do_lock).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(btns, text="UNLOCK", command=self.do_unlock).grid(row=0, column=2)

        # Status panel
        ttk.Separator(top).grid(row=3, column=0, columnspan=2, sticky="ew", pady=14)

        self.status_lbl = ttk.Label(top, text="Status: (click Get Status)", font=("Helvetica", 12))
        self.status_lbl.grid(row=4, column=0, columnspan=2, sticky="w")

        self.detail = tk.Text(top, height=8, width=60)
        self.detail.grid(row=5, column=0, columnspan=2, sticky="w", pady=(10, 0))
        self.detail.configure(state="disabled")

        for i in range(2):
            top.columnconfigure(i, weight=1)

    def client_cert(self):
        role = self.role.get()
        return CLIENTS[role]

    def show(self, obj):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", obj)
        self.detail.configure(state="disabled")

    def request(self, method, path, include_replay=False):
        cert = self.client_cert()
        try:
            resp = requests.request(
                method=method,
                url=f"{BASE_URL}{path}",
                cert=cert,
                verify=CA_FILE,
                headers=headers(self.sim_expired.get(), include_replay),
                timeout=5,
            )
            return resp
        except requests.exceptions.SSLError as e:
            messagebox.showerror("TLS Error", str(e))
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Network Error", str(e))
        return None

    def refresh_from_status(self, data):
        locked = data.get("locked")
        role = data.get("your_role")
        cn = data.get("your_cn")
        state = "LOCKED 🔒" if locked else "UNLOCKED 🔓"
        self.status_lbl.configure(text=f"Status: {state}  |  You: {role} ({cn})")
        self.show(json_pretty(data))

    def get_status(self):
        r = self.request("GET", "/api/status", include_replay=False)
        if not r:
            return
        if r.status_code != 200:
            self.show(r.text)
            self.status_lbl.configure(text=f"Status: ERROR ({r.status_code})")
            return
        self.refresh_from_status(r.json())

    def do_lock(self):
        r = self.request("POST", "/api/lock", include_replay=True)
        if not r:
            return
        if r.status_code != 200:
            self.show(r.text)
            self.status_lbl.configure(text=f"Status: ERROR ({r.status_code})")
            return
        self.refresh_from_status(r.json())

    def do_unlock(self):
        r = self.request("POST", "/api/unlock", include_replay=True)
        if not r:
            return
        if r.status_code != 200:
            self.show(r.text)
            self.status_lbl.configure(text=f"Status: ERROR ({r.status_code})")
            return
        self.refresh_from_status(r.json())

def json_pretty(d):
    import json
    return json.dumps(d, indent=2)

if __name__ == "__main__":
    App().mainloop()

