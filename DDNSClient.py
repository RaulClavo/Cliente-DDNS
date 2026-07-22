import json
import os
import re
import sys
import threading
import time
from datetime import datetime

import tkinter as tk
from tkinter import messagebox, ttk

import requests


APP_NAME = "DDNSClient"
WINDOW_SIZE = "900x520"


def script_directory():
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except NameError:
        return os.path.dirname(os.path.abspath(sys.argv[0]))


def user_data_directory():
    if os.name == "nt":
        base_directory = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
    else:
        base_directory = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base_directory, APP_NAME)


def persistent_profiles_file():
    return os.path.join(user_data_directory(), "profiles.json")


def bundled_profiles_file():
    return os.path.join(script_directory(), "profiles.json")


def profile_dns_name(profile):
    name = profile.get("name", "")
    if name in ("", "@"):
        return profile.get("domain", "")
    return f"{name}.{profile.get('domain', '')}"


def profile_api_name(profile):
    return "@" if profile.get("name") in ("", "@") else profile.get("name")


def normalize_profile(profile):
    normalized = dict(profile)
    normalized["api_key"] = str(normalized.get("api_key", "")).strip()
    normalized["api_secret"] = str(normalized.get("api_secret", "")).strip()
    normalized["domain"] = str(normalized.get("domain", "")).strip()
    name = str(normalized.get("name", "@")).strip()
    normalized["name"] = name if name else "@"
    normalized["ttl"] = int(normalized.get("ttl", 300))
    normalized["interval"] = int(normalized.get("interval", 60))
    normalized["enabled"] = bool(normalized.get("enabled", False))
    normalized["last_ip"] = str(normalized.get("last_ip", "")).strip()
    return normalized


def validate_profile_input(profile):
    if not profile["api_key"] or not profile["api_secret"] or not profile["domain"]:
        return "API Key, API Secret y Dominio son obligatorios"
    if profile["name"] != "@":
        if "." in profile["name"]:
            return "El Subdominio no debe contener puntos. Usa solo la etiqueta (ej: www) o @ para el raíz"
        if not re.fullmatch(r"[A-Za-z0-9-]{1,63}", profile["name"]):
            return "Subdominio inválido. Solo letras, números y guiones (1-63 caracteres)."
    return None


def build_dns_record(profile, ip):
    return {
        "type": "A",
        "name": profile_api_name(profile),
        "address": ip,
        "ttl": profile["ttl"],
    }


class DDNSWorker:
    def __init__(self, profile, log_cb, refresh_cb, save_cb):
        self.profile = profile
        self.log_cb = log_cb
        self.refresh_cb = refresh_cb
        self.save_cb = save_cb
        self.running = False
        self.last_public_ip = "-"
        self.last_action = "-"

    def dns_name(self):
        return profile_dns_name(self.profile)

    def api_url(self):
        return f"https://spaceship.dev/api/v1/dns/records/{self.profile['domain']}"

    def headers(self):
        return {
            "X-API-Key": self.profile["api_key"],
            "X-API-Secret": self.profile["api_secret"],
            "content-type": "application/json",
        }

    def get_public_ip(self):
        response = requests.get("https://api.ipify.org", timeout=10)
        response.raise_for_status()
        return response.text.strip()

    def request_with_error(self, method, **kwargs):
        response = requests.request(method, self.api_url(), headers=self.headers(), timeout=15, **kwargs)
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise Exception(f"HTTP {response.status_code}: {response.text}") from exc
        return response

    def delete_previous_record(self, previous_ip):
        payload = {"items": [build_dns_record(self.profile, previous_ip)]}
        self.request_with_error("DELETE", json=payload)

    def create_current_record(self, current_ip):
        payload = {
            "force": True,
            "items": [build_dns_record(self.profile, current_ip)],
        }
        self.request_with_error("PUT", json=payload)

    def sync_if_needed(self, public_ip):
        previous_ip = self.profile.get("last_ip", "")
        if public_ip == previous_ip:
            return "DNS ya actualizado"
        if previous_ip:
            self.delete_previous_record(previous_ip)
        self.create_current_record(public_ip)
        self.profile["last_ip"] = public_ip
        self.save_cb()
        return f"IP actualizada → {public_ip}"

    def wait_interval(self):
        for _ in range(self.profile["interval"]):
            if not self.running:
                break
            time.sleep(1)

    def loop(self):
        self.refresh_cb()

        while self.running:
            try:
                public_ip = self.get_public_ip()
                self.last_public_ip = public_ip
                result = self.sync_if_needed(public_ip)
                self.log_cb(self.dns_name(), result)
            except Exception as exc:
                self.log_cb(self.dns_name(), f"Error: {exc}")

            self.refresh_cb()
            self.wait_interval()

        self.refresh_cb()

    def start(self):
        if not self.running:
            self.running = True
            threading.Thread(target=self.loop, daemon=True).start()

    def stop(self):
        self.running = False


class DDNSApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry(WINDOW_SIZE)
        self.resizable(False, False)
        self.profiles = []
        self.workers = {}
        self.store_lock = threading.Lock()
        self.main_thread = threading.current_thread()
        self.data_file = persistent_profiles_file()
        self.fallback_data_file = bundled_profiles_file()
        self.load_profiles()
        self.build_ui()
        self.start_enabled_profiles()
        self.refresh_tree()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        for worker in list(self.workers.values()):
            try:
                worker.stop()
            except Exception:
                pass
        self.save_profiles()
        self.destroy()

    def is_main_thread(self):
        return threading.current_thread() is self.main_thread

    def profile_id(self, profile):
        return profile_dns_name(profile)

    def load_profiles(self):
        source_file = self.data_file if os.path.exists(self.data_file) else self.fallback_data_file
        try:
            if os.path.exists(source_file):
                with open(source_file, "r", encoding="utf-8") as file_handle:
                    raw_profiles = json.load(file_handle)
            else:
                raw_profiles = []
        except Exception:
            raw_profiles = []

        self.profiles = []
        for profile in raw_profiles:
            try:
                self.profiles.append(normalize_profile(profile))
            except Exception:
                continue

        if not os.path.exists(self.data_file):
            self.save_profiles()

    def save_profiles(self):
        with self.store_lock:
            try:
                os.makedirs(os.path.dirname(self.data_file), exist_ok=True)
                with open(self.data_file, "w", encoding="utf-8") as file_handle:
                    json.dump(self.profiles, file_handle, ensure_ascii=False, indent=2)
            except Exception:
                pass

    def build_ui(self):
        ttk.Label(self, text="DDNS Profiles", font=("Segoe UI", 11, "bold")).pack(pady=5)

        self.tree = ttk.Treeview(self, columns=("name", "state", "ip", "last"), show="headings", height=10)
        self.tree.heading("name", text="Nombre DNS")
        self.tree.heading("state", text="Estado")
        self.tree.heading("ip", text="Última IP pública")
        self.tree.heading("last", text="Última acción")
        self.tree.column("name", width=280)
        self.tree.column("state", width=90, anchor="center")
        self.tree.column("ip", width=150, anchor="center")
        self.tree.column("last", width=300, anchor="center")
        self.tree.pack(fill="x", padx=10)

        buttons = ttk.Frame(self)
        buttons.pack(pady=5)
        ttk.Button(buttons, text="➕ Añadir", command=self.add_profile).pack(side="left", padx=5)
        ttk.Button(buttons, text="➖ Eliminar", command=self.delete_profile).pack(side="left", padx=5)
        ttk.Button(buttons, text="▶ Activar", command=self.activate).pack(side="left", padx=5)
        ttk.Button(buttons, text="⏹ Desactivar", command=self.deactivate).pack(side="left", padx=5)

        ttk.Label(self, text="Log").pack(pady=5)
        self.logbox = tk.Text(self, height=10, state="disabled")
        self.logbox.pack(fill="both", padx=10)

    def add_profile(self):
        win = tk.Toplevel(self)
        win.title("Nuevo perfil DDNS")
        win.geometry("320x380")

        fields = {}
        for label in ["API Key", "API Secret", "Dominio", "Subdominio", "TTL", "Intervalo"]:
            ttk.Label(win, text=label).pack(pady=2)
            entry = ttk.Entry(win)
            entry.pack()
            fields[label] = entry

        fields["Subdominio"].insert(0, "@")
        fields["TTL"].insert(0, "300")
        fields["Intervalo"].insert(0, "60")

        def save():
            profile = normalize_profile({
                "api_key": fields["API Key"].get(),
                "api_secret": fields["API Secret"].get(),
                "domain": fields["Dominio"].get(),
                "name": fields["Subdominio"].get(),
                "ttl": fields["TTL"].get(),
                "interval": fields["Intervalo"].get(),
                "enabled": False,
                "last_ip": "",
            })

            validation_error = validate_profile_input(profile)
            if validation_error:
                messagebox.showerror("Error", validation_error)
                return

            self.profiles.append(profile)
            self.save_profiles()
            self.refresh_tree()
            win.destroy()

        ttk.Button(win, text="Guardar", command=save).pack(pady=10)

    def get_selected_profile(self):
        selection = self.tree.selection()
        if not selection:
            return None, None
        dns = selection[0]
        profile = next((item for item in self.profiles if self.profile_id(item) == dns), None)
        return dns, profile

    def delete_profile(self):
        dns, profile = self.get_selected_profile()
        if not dns or profile is None:
            return

        worker = self.workers.pop(dns, None)
        if worker is not None:
            worker.stop()

        self.profiles = [item for item in self.profiles if self.profile_id(item) != dns]
        self.save_profiles()
        self.refresh_tree()

    def worker_for_profile(self, profile):
        dns = self.profile_id(profile)
        worker = self.workers.get(dns)
        if worker is None:
            worker = DDNSWorker(profile, self.log, self.refresh_tree, self.save_profiles)
            self.workers[dns] = worker
        return worker

    def start_enabled_profiles(self):
        for profile in self.profiles:
            if not profile.get("enabled"):
                continue
            worker = self.worker_for_profile(profile)
            if not worker.running:
                worker.start()

    def activate(self):
        dns, profile = self.get_selected_profile()
        if dns is None or profile is None:
            return

        profile["enabled"] = True
        worker = self.worker_for_profile(profile)
        if not worker.running:
            worker.start()
        self.save_profiles()
        self.refresh_tree()

    def deactivate(self):
        dns, profile = self.get_selected_profile()
        if dns is None or profile is None:
            return

        worker = self.workers.get(dns)
        if worker is not None:
            worker.stop()

        profile["enabled"] = False
        self.save_profiles()
        self.refresh_tree()

    def refresh_tree(self):
        if not self.is_main_thread():
            try:
                self.after(0, self.refresh_tree)
            except Exception:
                pass
            return

        self.tree.delete(*self.tree.get_children())
        for profile in self.profiles:
            dns = self.profile_id(profile)
            worker = self.workers.get(dns)
            state = "Activo" if worker and worker.running else "Detenido"
            ip = worker.last_public_ip if worker and worker.running else profile.get("last_ip", "-") or "-"
            last_action = worker.last_action if worker else "-"
            self.tree.insert("", "end", iid=dns, values=(dns, state, ip, last_action))

    def append_log(self, dns, msg):
        self.logbox.config(state="normal")
        self.logbox.insert("end", f"[{dns}] {msg}\n")
        self.logbox.see("end")
        self.logbox.config(state="disabled")

    def log(self, dns, msg):
        if not self.is_main_thread():
            try:
                self.after(0, lambda: self.log(dns, msg))
            except Exception:
                pass
            return

        timestamped = f"{datetime.now().strftime('%H:%M:%S')} {msg}"
        self.append_log(dns, msg)

        worker = self.workers.get(dns)
        if worker is not None:
            worker.last_action = timestamped

        if dns in self.tree.get_children():
            self.tree.set(dns, "last", timestamped)


if __name__ == "__main__":
    app = DDNSApp()
    app.mainloop()
