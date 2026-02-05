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


class DDNSWorker:
    def __init__(self, profile, log_cb, refresh_cb):
        self.profile = profile
        self.log_cb = log_cb
        self.refresh_cb = refresh_cb
        self.running = False
        self.last_public_ip = "-"
        self.last_action = "-"

    def dns_name(self):
        name = self.profile.get("name", "")
        if name == "@" or name == "":
            return f"{self.profile['domain']}"
        return f"{name}.{self.profile['domain']}"

    def get_public_ip(self):
        return requests.get("https://api.ipify.org", timeout=10).text.strip()

    def get_dns_records(self):
        url = f"https://spaceship.dev/api/v1/dns/records/{self.profile['domain']}"
        headers = {
            "X-API-Key": self.profile["api_key"],
            "X-API-Secret": self.profile["api_secret"]
        }
        params = {"take": 100, "skip": 0}
        r = requests.get(url, headers=headers, params=params, timeout=15)
        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            raise Exception(f"HTTP {r.status_code}: {r.text}") from e
        return r.json().get("items", [])

    def update_dns(self, ip):
        p = self.profile
        url = f"https://spaceship.dev/api/v1/dns/records/{p['domain']}"
        headers = {
            "X-API-Key": p["api_key"],
            "X-API-Secret": p["api_secret"],
            "content-type": "application/json"
        }
        name_for_api = "@" if p.get("name") in ("@", "") else p.get("name")
        payload = {
            "force": True,
            "items": [{
                "type": "A",
                "name": name_for_api,
                "address": ip,
                "ttl": p["ttl"]
            }]
        }
        r = requests.put(url, json=payload, headers=headers, timeout=15)
        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            raise Exception(f"HTTP {r.status_code}: {r.text}") from e

    def loop(self):
        self.running = True
        self.refresh_cb()

        while self.running:
            try:
                public_ip = self.get_public_ip()
                self.last_public_ip = public_ip

                records = self.get_dns_records()
                profile_name_for_api = "@" if self.profile.get("name") in ("@", "") else self.profile.get("name")
                record = next(
                    (r for r in records if r["type"] == "A" and r.get("name", "") == profile_name_for_api),
                    None
                )

                if record is None:
                    self.update_dns(public_ip)
                    self.log_cb(self.dns_name(), "Registro creado")
                elif record.get("value") != public_ip:
                    self.update_dns(public_ip)
                    self.log_cb(self.dns_name(), f"IP actualizada → {public_ip}")
                else:
                    self.log_cb(self.dns_name(), "DNS ya actualizado")

            except Exception as e:
                self.log_cb(self.dns_name(), f"Error: {e}")

            self.refresh_cb()

            for _ in range(self.profile["interval"]):
                if not self.running:
                    break
                time.sleep(1)

        self.refresh_cb()

    def start(self):
        if not self.running:
            threading.Thread(target=self.loop, daemon=True).start()

    def stop(self):
        self.running = False


class DDNSApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DDNSClient")
        self.geometry("900x520")
        self.resizable(False, False)
        self.profiles = []
        self.workers = {}
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
        except NameError:
            script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        self.data_file = os.path.join(script_dir, "profiles.json")
        self.load_profiles()
        self.build_ui()
        self.start_enabled_profiles()
        try:
            self.refresh_tree()
        except Exception:
            pass
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        for w in list(self.workers.values()):
            try:
                w.stop()
            except Exception:
                pass
        self.save_profiles()
        self.destroy()

    def profile_id(self, profile):
        name = profile.get("name", "")
        if name in ("@", ""):
            return profile.get("domain", "")
        return f"{name}.{profile.get('domain', '')}"

    def load_profiles(self):
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, "r", encoding="utf-8") as f:
                    self.profiles = json.load(f)
            else:
                self.profiles = []
        except Exception:
            self.profiles = []
        for p in self.profiles:
            if "enabled" not in p:
                p["enabled"] = False

    def save_profiles(self):
        try:
            with open(self.data_file, "w", encoding="utf-8") as f:
                json.dump(self.profiles, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def build_ui(self):
        ttk.Label(self, text="DDNS Profiles", font=("Segoe UI", 11, "bold")).pack(pady=5)
        self.tree = ttk.Treeview(self,columns=("name", "state", "ip", "last"),show="headings",height=10)
        self.tree.heading("name", text="Nombre DNS")
        self.tree.heading("state", text="Estado")
        self.tree.heading("ip", text="Última IP pública")
        self.tree.heading("last", text="Última acción")
        self.tree.column("name", width=280)
        self.tree.column("state", width=90, anchor="center")
        self.tree.column("ip", width=150, anchor="center")
        self.tree.column("last", width=300, anchor="center")
        self.tree.pack(fill="x", padx=10)
        btns = ttk.Frame(self)
        btns.pack(pady=5)
        ttk.Button(btns, text="➕ Añadir", command=self.add_profile).pack(side="left", padx=5)
        ttk.Button(btns, text="➖ Eliminar", command=self.delete_profile).pack(side="left", padx=5)
        ttk.Button(btns, text="▶ Activar", command=self.activate).pack(side="left", padx=5)
        ttk.Button(btns, text="⏹ Desactivar", command=self.deactivate).pack(side="left", padx=5)
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
            e = ttk.Entry(win)
            e.pack()
            fields[label] = e
        fields["Subdominio"].insert(0, "@")
        fields["TTL"].insert(0, "300")
        fields["Intervalo"].insert(0, "60")

        def save():
            profile = {
                "api_key": fields["API Key"].get().strip(),
                "api_secret": fields["API Secret"].get().strip(),
                "domain": fields["Dominio"].get().strip(),
                "name": fields["Subdominio"].get().strip(),
                "ttl": fields["TTL"].get().strip(),
                "interval": fields["Intervalo"].get().strip(),
                "enabled": False
            }
            if not profile["api_key"] or not profile["api_secret"] or not profile["domain"]:
                messagebox.showerror("Error", "API Key, API Secret y Dominio son obligatorios")
                return
            try:
                profile["ttl"] = int(profile["ttl"])
                profile["interval"] = int(profile["interval"])
            except Exception:
                messagebox.showerror("Error", "TTL e Intervalo deben ser números enteros")
                return
            if profile["name"] == "":
                profile["name"] = "@"
            if profile["name"] != "@":
                if "." in profile["name"]:
                    messagebox.showerror("Error", "El Subdominio no debe contener puntos. Usa sólo la etiqueta (ej: www) o @ para el raíz")
                    return
                if not re.fullmatch(r"[A-Za-z0-9-]{1,63}", profile["name"]):
                    messagebox.showerror("Error", "Subdominio inválido. Sólo letras, números y guiones (1-63 caracteres).")
                    return
            self.profiles.append(profile)
            self.save_profiles()
            self.refresh_tree()
            win.destroy()
        ttk.Button(win, text="Guardar", command=save).pack(pady=10)

    def delete_profile(self):
        sel = self.tree.selection()
        if not sel:return
        dns = sel[0]
        if dns in self.workers:
            self.workers[dns].stop()
            del self.workers[dns]
        self.profiles = [p for p in self.profiles if self.profile_id(p) != dns]
        self.save_profiles()
        self.refresh_tree()

    def start_enabled_profiles(self):
        for p in self.profiles:
            if not p.get("enabled"):
                continue
            dns = self.profile_id(p)
            if dns in self.workers and self.workers[dns].running:
                continue
            worker = DDNSWorker(p, self.log, self.refresh_tree)
            self.workers[dns] = worker
            worker.start()

    def activate(self):
        sel = self.tree.selection()
        if not sel:return
        dns = sel[0]
        if dns in self.workers and self.workers[dns].running:return
        profile = next(p for p in self.profiles if self.profile_id(p) == dns)
        worker = DDNSWorker(profile, self.log, self.refresh_tree)
        self.workers[dns] = worker
        worker.start()
        profile["enabled"] = True
        self.save_profiles()
        self.refresh_tree()

    def deactivate(self):
        sel = self.tree.selection()
        if not sel:return
        dns = sel[0]
        if dns in self.workers:
            self.workers[dns].stop()
        profile = next((p for p in self.profiles if self.profile_id(p) == dns), None)
        if profile is not None:
            profile["enabled"] = False
            self.save_profiles()
        self.refresh_tree()

    def refresh_tree(self):
        self.tree.delete(*self.tree.get_children())
        for p in self.profiles:
            dns = self.profile_id(p)
            worker = self.workers.get(dns)
            state = "Activo" if worker and worker.running else "Detenido"
            ip = worker.last_public_ip if worker else "-"
            last = worker.last_action if worker else "-"
            self.tree.insert("", "end", iid=dns, values=(dns, state, ip, last))

    def log(self, dns, msg):
        self.logbox.config(state="normal")
        self.logbox.insert("end", f"[{dns}] {msg}\n")
        self.logbox.see("end")
        self.logbox.config(state="disabled")
        timestamped = f"{datetime.now().strftime('%H:%M:%S')} {msg}"
        if dns in self.workers:
            try:
                self.workers[dns].last_action = timestamped
            except Exception:
                pass
        if dns in self.tree.get_children():
            self.tree.set(dns, "last", timestamped)


if __name__ == "__main__":
    app = DDNSApp()
    app.mainloop()
