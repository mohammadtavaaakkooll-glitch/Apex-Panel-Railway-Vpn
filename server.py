"""
APEX MTProto Proxy - Server Manager
"""
import os
import json
import uuid
import subprocess
import threading
import time
import secrets
from pathlib import Path
from datetime import datetime, timedelta

BASE_DIR = Path(__file__).parent
DATA_DIR = Path(os.environ.get("DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(exist_ok=True, parents=True)

DB_FILE = DATA_DIR / "db.json"
LOG_FILE = DATA_DIR / "logs.json"
CONFIG_FILE = DATA_DIR / "mtproto.json"


def load_json(path, default):
    if not path.exists():
        save_json(path, default)
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def add_log(action, detail=""):
    logs = load_json(LOG_FILE, [])
    logs.insert(0, {
        "time": datetime.now().isoformat(),
        "action": action,
        "detail": detail
    })
    save_json(LOG_FILE, logs[:200])


class MTProtoManager:
    def __init__(self):
        self.process = None
        self.started_at = None
        self.db = load_json(DB_FILE, {
            "admin": None,
            "users": [],
            "settings": self.default_settings()
        })

    @staticmethod
    def default_settings():
        return {
            "panel_name": "Apex MTProto",
            "server_ip": "your-app.up.railway.app",
            "port": int(os.environ.get("PORT", 8080)),
            "secret": secrets.token_hex(16),
            "proxy_tag": "APEX",
            "max_connections": 10000,
            "fake_tls_domain": "www.google.com"
        }

    def reload(self):
        self.db = load_json(DB_FILE, self.db)

    def save(self):
        save_json(DB_FILE, self.db)

    # ---------- Admin ----------
    def set_admin(self, username, password_hash):
        self.db["admin"] = {
            "username": username,
            "password": password_hash,
            "created_at": datetime.now().isoformat()
        }
        self.save()

    def get_admin(self):
        return self.db.get("admin")

    # ---------- MTProto Proxy ----------
    def start_proxy(self):
        if self.process and self.process.poll() is None:
            return False, "already running"

        self.reload()
        s = self.db["settings"]

        config = {
            "secret": s["secret"],
            "bind-to": f"0.0.0.0:{s['port']}",
            "concurrency": s.get("max_connections", 10000),
            "domain-fronting-port": 443,
            "prefer-ip": "prefer-ipv6",
            "tolerate-time-skewness": True,
            "secure-mode": True,
            "debug": False
        }
        save_json(CONFIG_FILE, config)

        cmd = ["mtg", "run", str(CONFIG_FILE)]
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            self.started_at = datetime.now()
            time.sleep(1)
            if self.process.poll() is not None:
                err = self.process.stderr.read()
                self.process = None
                return False, f"mtg failed: {err[:200]}"
            add_log("proxy_started", f"پورت {s['port']}")
            return True, "started"
        except Exception as e:
            return False, str(e)

    def stop_proxy(self):
        if not self.process or self.process.poll() is not None:
            return False, "not running"
        self.process.terminate()
        self.process = None
        add_log("proxy_stopped", "")
        return True, "stopped"

    def restart_proxy(self):
        self.stop_proxy()
        time.sleep(0.5)
        return self.start_proxy()

    def is_running(self):
        return self.process is not None and self.process.poll() is None

    def build_link(self, secret=None):
        s = self.db["settings"]
        sec = secret or s["secret"]
        return f"tg://proxy?server={s['server_ip']}&port={s['port']}&secret={sec}&tag={s.get('proxy_tag','APEX')}"

    def build_https_link(self, secret=None):
        s = self.db["settings"]
        sec = secret or s["secret"]
        return f"https://t.me/proxy?server={s['server_ip']}&port={s['port']}&secret={sec}"

    # ---------- Users ----------
    def list_users(self):
        self.reload()
        return self.db["users"]

    def create_user(self, name, expire_days=0, max_connections=100):
        self.reload()
        s = self.db["settings"]
        user_secret = secrets.token_hex(16)
        user = {
            "id": str(uuid.uuid4()),
            "name": name,
            "secret": user_secret,
            "max_connections": max_connections,
            "status": "active",
            "expire_at": (datetime.now() + timedelta(days=expire_days)).isoformat() if expire_days > 0 else None,
            "created_at": datetime.now().isoformat(),
            "last_seen": None,
            "connections": 0,
            "link": f"tg://proxy?server={s['server_ip']}&port={s['port']}&secret={user_secret}&tag={s.get('proxy_tag','APEX')}",
            "https_link": f"https://t.me/proxy?server={s['server_ip']}&port={s['port']}&secret={user_secret}"
        }
        self.db["users"].append(user)
        self.save()
        add_log("user_created", f"{name}")
        return user

    def delete_user(self, user_id):
        self.reload()
        self.db["users"] = [u for u in self.db["users"] if u["id"] != user_id]
        self.save()
        add_log("user_deleted", user_id[:8])
        return True

    def get_user(self, user_id):
        self.reload()
        for u in self.db["users"]:
            if u["id"] == user_id:
                return u
        return None

    def update_user(self, user_id, data):
        self.reload()
        for u in self.db["users"]:
            if u["id"] == user_id:
                for k in ("name", "status", "max_connections"):
                    if k in data:
                        u[k] = data[k]
                self.save()
                return u
        return None

    def bulk_create(self, prefix, count, expire_days=0):
        created = []
        for i in range(count):
            created.append(self.create_user(f"{prefix}_{i+1}", expire_days))
        return created

    # ---------- Stats ----------
    def get_stats(self):
        self.reload()
        users = self.db["users"]
        return {
            "total_users": len(users),
            "active_users": len([u for u in users if u["status"] == "active"]),
            "connections": sum(u.get("connections", 0) for u in users),
            "proxy_running": self.is_running()
        }


mtproto = MTProtoManager()
