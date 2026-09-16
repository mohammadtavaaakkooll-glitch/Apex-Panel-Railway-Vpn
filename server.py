"""
APEX PANEL - Xray Server Manager
مدیریت کامل Xray Core با API
"""
import os
import json
import uuid
import subprocess
import threading
import time
import shutil
import requests
from datetime import datetime, timedelta
from pathlib import Path

# ==================== PATHS ====================
BASE_DIR = Path(__file__).parent
DATA_DIR = Path(os.environ.get("DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(exist_ok=True, parents=True)

DB_FILE = DATA_DIR / "db.json"
LOG_FILE = DATA_DIR / "logs.json"
IP_LOG_FILE = DATA_DIR / "ip_log.json"
XRAY_CONFIG = DATA_DIR / "xray_config.json"
XRAY_STATS = DATA_DIR / "xray_stats.json"

XRAY_BIN = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
XRAY_API_PORT = int(os.environ.get("XRAY_API_PORT", "10085"))
XRAY_API_HOST = os.environ.get("XRAY_API_HOST", "127.0.0.1")


# ==================== JSON HELPERS ====================
def load_json(path, default):
    if not path.exists():
        save_json(path, default)
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ==================== XRAY CORE ====================
class XrayCore:
    """
    مدیریت کامل Xray:
    - ساخت کانفیگ
    - اجرا/توقف
    - اضافه/حذف کاربر
    - آمار زنده
    """

    def __init__(self):
        self.process = None
        self.started_at = None
        self._lock = threading.Lock()

    # ---------- config ----------
    def build_config(self, settings, users):
        """ساخت xray_config.json قدرتمند"""
        inbounds = [
            # VLESS WebSocket
            {
                "tag": "vless-ws",
                "listen": "0.0.0.0",
                "port": int(settings.get("vless_ws_port", 10001)),
                "protocol": "vless",
                "settings": {
                    "clients": [],
                    "decryption": "none",
                    "fallbacks": []
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {
                        "path": settings.get("vless_ws_path", "/vl-ws"),
                        "headers": {}
                    }
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": False
                }
            },
            # VLESS TCP (Vision)
            {
                "tag": "vless-tcp",
                "listen": "0.0.0.0",
                "port": int(settings.get("vless_tcp_port", 10002)),
                "protocol": "vless",
                "settings": {
                    "clients": [],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "none",
                    "tcpSettings": {
                        "header": {"type": "none"}
                    }
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"]
                }
            },
            # VMess WebSocket
            {
                "tag": "vmess-ws",
                "listen": "0.0.0.0",
                "port": int(settings.get("vmess_ws_port", 10003)),
                "protocol": "vmess",
                "settings": {
                    "clients": []
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {
                        "path": settings.get("vmess_ws_path", "/vm-ws")
                    }
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"]
                }
            },
            # Trojan WebSocket
            {
                "tag": "trojan-ws",
                "listen": "0.0.0.0",
                "port": int(settings.get("trojan_ws_port", 10004)),
                "protocol": "trojan",
                "settings": {
                    "clients": []
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {
                        "path": settings.get("trojan_ws_path", "/tj-ws")
                    }
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"]
                }
            },
        ]

        # اضافه کردن کاربرا به inboundهای مربوطه
        for user in users:
            if user.get("status") != "active":
                continue

            # چک انقضا
            if user.get("expire_at"):
                try:
                    exp = datetime.fromisoformat(user["expire_at"])
                    if exp < datetime.now():
                        continue
                except:
                    pass

            # چک حجم
            if user.get("used", 0) >= user.get("size", 0):
                continue

            client_base = {
                "id": user["uuid"],
                "email": f"{user['id']}@{user['name']}",
                "level": 0
            }

            # VLESS WS
            if user.get("protocol") in ("vless", None):
                inbounds[0]["settings"]["clients"].append({
                    **client_base,
                    "flow": ""
                })
                inbounds[1]["settings"]["clients"].append({
                    **client_base,
                    "flow": "xtls-rprx-vision"
                })

            # VMess
            if user.get("protocol") in ("vmess", None):
                inbounds[2]["settings"]["clients"].append({
                    **client_base,
                    "alterId": 0,
                    "security": "auto"
                })

            # Trojan
            if user.get("protocol") in ("trojan", None):
                inbounds[3]["settings"]["clients"].append({
                    "password": user["uuid"],
                    "email": f"{user['id']}@{user['name']}"
                })

        config = {
            "log": {
                "loglevel": "warning",
                "access": str(DATA_DIR / "xray_access.log"),
                "error": str(DATA_DIR / "xray_error.log")
            },
            "dns": {
                "servers": [
                    {"address": "1.1.1.1", "domains": ["geosite:geolocation-!cn"]},
                    {"address": "8.8.8.8", "domains": ["geosite:geolocation-!cn"]},
                    "localhost"
                ],
                "queryStrategy": "UseIPv4"
            },
            "api": {
                "tag": "api",
                "services": ["HandlerService", "LoggerService", "StatsService"]
            },
            "stats": {},
            "policy": {
                "levels": {
                    "0": {
                        "statsUserUplink": True,
                        "statsUserDownlink": True,
                        "handshake": 4,
                        "connIdle": 300,
                        "uplinkOnly": 1,
                        "downlinkOnly": 1
                    }
                },
                "system": {
                    "statsInboundUplink": True,
                    "statsInboundDownlink": True,
                    "statsOutboundUplink": True,
                    "statsOutboundDownlink": True
                }
            },
            "inbounds": [
                # API inbound
                {
                    "tag": "api",
                    "listen": XRAY_API_HOST,
                    "port": XRAY_API_PORT,
                    "protocol": "dokodemo-door",
                    "settings": {"address": XRAY_API_HOST},
                    "sniffing": {"enabled": False},
                    "streamSettings": {"network": "tcp"}
                },
                *inbounds
            ],
            "outbounds": [
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {"domainStrategy": "UseIPv4"}
                },
                {
                    "tag": "block",
                    "protocol": "blackhole",
                    "settings": {"response": {"type": "http"}}
                }
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {
                        "type": "field",
                        "inboundTag": ["api"],
                        "outboundTag": "api"
                    },
                    {
                        "type": "field",
                        "ip": ["geoip:private"],
                        "outboundTag": "block"
                    },
                    {
                        "type": "field",
                        "domain": ["geosite:category-ads-all"],
                        "outboundTag": "block"
                    },
                    {
                        "type": "field",
                        "protocol": ["bittorrent"],
                        "outboundTag": "block"
                    }
                ]
            }
        }

        return config

    # ---------- process ----------
    def is_running(self):
        return self.process is not None and self.process.poll() is None

    def start(self):
        """اجرای Xray"""
        with self._lock:
            if self.is_running():
                return False, "already running"

            if not Path(XRAY_BIN).exists():
                # جستجوی Xray تو مسیرهای دیگه
                for p in ["/usr/bin/xray", "/usr/local/bin/xray", "./xray"]:
                    if Path(p).exists():
                        break

            try:
                cmd = [XRAY_BIN, "run", "-config", str(XRAY_CONFIG)]
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
                    return False, f"Xray crashed: {err[:200]}"

                return True, "started"
            except Exception as e:
                return False, str(e)

    def stop(self):
        """توقف Xray"""
        with self._lock:
            if not self.is_running():
                return False, "not running"
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except:
                self.process.kill()
            self.process = None
            return True, "stopped"

    def restart(self):
        """ری‌استارت Xray"""
        self.stop()
        time.sleep(0.5)
        return self.start()

    # ---------- stats ----------
    def get_stats(self):
        """خوندن آمار از Xray API"""
        try:
            result = subprocess.run(
                [
                    XRAY_BIN, "api", "statsquery",
                    f"--server={XRAY_API_HOST}:{XRAY_API_PORT}"
                ],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                return {}

            stats = {}
            for line in result.stdout.strip().split("\n"):
                if not line or ":" not in line:
                    continue
                parts = line.split(":")
                if len(parts) >= 2:
                    name = parts[0].strip().strip('"')
                    try:
                        value = int(parts[1].strip())
                        stats[name] = value
                    except:
                        pass
            return stats
        except Exception:
            return {}

    def get_user_traffic(self, user_email):
        """مصرف یک کاربر خاص"""
        stats = self.get_stats()
        uplink = 0
        downlink = 0
        for k, v in stats.items():
            if user_email in k:
                if "uplink" in k:
                    uplink += v
                elif "downlink" in k:
                    downlink += v
        return {"up": uplink, "down": downlink, "total": uplink + downlink}

    def reset_user_traffic(self, user_email):
        """ریست مصرف کاربر"""
        try:
            subprocess.run(
                [
                    XRAY_BIN, "api", "stats",
                    f"--server={XRAY_API_HOST}:{XRAY_API_PORT}",
                    "-reset",
                    f"user>>>{user_email}>>>traffic>>>uplink"
                ],
                timeout=5, capture_output=True
            )
            subprocess.run(
                [
                    XRAY_BIN, "api", "stats",
                    f"--server={XRAY_API_HOST}:{XRAY_API_PORT}",
                    "-reset",
                    f"user>>>{user_email}>>>traffic>>>downlink"
                ],
                timeout=5, capture_output=True
            )
            return True
        except:
            return False


# ==================== USER MANAGER ====================
class UserManager:
    """مدیریت کاربران با دیتابیس JSON"""

    def __init__(self, xray: XrayCore):
        self.xray = xray
        self.db = load_json(DB_FILE, {
            "admin": None,
            "users": [],
            "settings": self.default_settings()
        })

    @staticmethod
    def default_settings():
        return {
            "panel_name": "Apex Panel",
            "server_ip": "servconfmmd.ir",
            "server_port": 443,
            "sub_path": "/vl-ws",
            "vless_ws_path": "/vl-ws",
            "vless_ws_port": 10001,
            "vless_tcp_port": 10002,
            "vmess_ws_path": "/vm-ws",
            "vmess_ws_port": 10003,
            "trojan_ws_path": "/tj-ws",
            "trojan_ws_port": 10004,
            "sni": "servconfmmd.ir",
            "fp": "chrome",
            "alpn": "http/1.1",
            "sub_domain": "sub.apex.ir",
            "status_domain": "status.apex.ir",
            "ip_lock_enabled": False,
            "max_ips_per_user": 1,
            "auto_restart": True,
            "traffic_check_interval": 60
        }

    def reload(self):
        self.db = load_json(DB_FILE, self.db)
        return self.db

    def save(self):
        save_json(DB_FILE, self.db)

    # ---------- admin ----------
    def set_admin(self, username, password_hash):
        self.db["admin"] = {
            "username": username,
            "password": password_hash,
            "created_at": datetime.now().isoformat()
        }
        self.save()

    def get_admin(self):
        return self.db.get("admin")

    # ---------- users ----------
    def list_users(self):
        self.reload()
        return self.db["users"]

    def get_user(self, user_id):
        self.reload()
        for u in self.db["users"]:
            if u["id"] == user_id:
                return u
        return None

    def get_user_by_uuid(self, user_uuid):
        self.reload()
        for u in self.db["users"]:
            if u["uuid"] == user_uuid:
                return u
        return None

    def create_user(self, name, size_gb, expire_days=0, protocol="vless"):
        self.reload()
        s = self.db["settings"]

        user_uuid = str(uuid.uuid4())
        user_id = str(uuid.uuid4())

        # ساخت لینک‌ها
        links = self.build_links(user_uuid, name, s)

        expire_at = None
        if expire_days and int(expire_days) > 0:
            expire_at = (datetime.now() + timedelta(days=int(expire_days))).isoformat()

        user = {
            "id": user_id,
            "name": name,
            "size": int(size_gb),
            "used": 0,
            "uuid": user_uuid,
            "protocol": protocol,
            "links": links,
            "sub_link": f"https://{s['sub_domain']}/sub/{user_uuid}",
            "status": "active",
            "expire_at": expire_at,
            "created_at": datetime.now().isoformat(),
            "last_seen": None,
            "connections": 0,
            "allowed_ips": []
        }

        self.db["users"].append(user)
        self.save()

        # ری‌استارت Xray
        self.apply_to_xray()
        return user

    def build_links(self, user_uuid, name, s):
        """ساخت همه لینک‌ها (VLESS WS/TCP, VMess, Trojan)"""
        host = s["server_ip"]
        port = s["server_port"]
        sni = s["sni"]
        fp = s["fp"]
        alpn = s["alpn"]

        links = {}

        # VLESS WS
        links["vless_ws"] = (
            f"vless://{user_uuid}@{host}:{port}"
            f"?type=ws&security=tls&path={s['vless_ws_path']}"
            f"&host={host}&sni={sni}&fp={fp}&alpn={alpn}"
            f"&encryption=none#{name}-VLESS-WS"
        )

        # VLESS TCP Vision
        links["vless_tcp"] = (
            f"vless://{user_uuid}@{host}:{port}"
            f"?type=tcp&security=tls&flow=xtls-rprx-vision"
            f"&sni={sni}&fp={fp}&alpn={alpn}"
            f"&encryption=none#{name}-VLESS-TCP"
        )

        # VMess WS
        vmess_cfg = {
            "v": "2",
            "ps": f"{name}-VMess",
            "add": host,
            "port": str(port),
            "id": user_uuid,
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": host,
            "path": s["vmess_ws_path"],
            "tls": "tls",
            "sni": sni,
            "alpn": alpn,
            "fp": fp
        }
        import base64
        vmess_b64 = base64.b64encode(json.dumps(vmess_cfg).encode()).decode()
        links["vmess_ws"] = f"vmess://{vmess_b64}"

        # Trojan WS
        links["trojan_ws"] = (
            f"trojan://{user_uuid}@{host}:{port}"
            f"?type=ws&security=tls&path={s['trojan_ws_path']}"
            f"&host={host}&sni={sni}&fp={fp}&alpn={alpn}"
            f"#{name}-Trojan"
        )

        return links

    def update_user(self, user_id, data):
        self.reload()
        for u in self.db["users"]:
            if u["id"] == user_id:
                for k in ("name", "size", "status", "expire_at", "protocol"):
                    if k in data:
                        u[k] = int(data[k]) if k == "size" else data[k]
                self.save()
                self.apply_to_xray()
                return u
        return None

    def delete_user(self, user_id):
        self.reload()
        self.db["users"] = [u for u in self.db["users"] if u["id"] != user_id]
        self.save()
        self.apply_to_xray()
        return True

    def reset_user(self, user_id):
        self.reload()
        for u in self.db["users"]:
            if u["id"] == user_id:
                u["used"] = 0
                u["connections"] = 0
                self.save()
                self.xray.reset_user_traffic(f"{u['id']}@{u['name']}")
                return u
        return None

    def bulk_create(self, prefix, count, size_gb, expire_days=0):
        created = []
        for i in range(count):
            name = f"{prefix}_{i+1}"
            user = self.create_user(name, size_gb, expire_days)
            created.append(user)
        return created

    # ---------- xray apply ----------
    def apply_to_xray(self):
        """ساخت کانفیگ و ری‌استارت Xray"""
        self.reload()
        config = self.xray.build_config(self.db["settings"], self.db["users"])
        save_json(XRAY_CONFIG, config)

        if self.db["settings"].get("auto_restart", True):
            self.xray.restart()

    def start_xray(self):
        return self.xray.start()

    def stop_xray(self):
        return self.xray.stop()

    def restart_xray(self):
        return self.xray.restart()

    # ---------- stats ----------
    def update_usage(self):
        """آپدیت مصرف همه کاربرا از Xray API"""
        self.reload()
        stats = self.xray.get_stats()
        changed = False

        for u in self.db["users"]:
            email = f"{u['id']}@{u['name']}"
            up = down = 0
            for k, v in stats.items():
                if email in k:
                    if "uplink" in k:
                        up += v
                    elif "downlink" in k:
                        down += v

            new_used = round((up + down) / (1024**3), 3)
            if new_used != u.get("used", 0):
                u["used"] = new_used
                u["last_seen"] = datetime.now().isoformat()
                changed = True

            # چک حجم
            if u["used"] >= u["size"] and u["status"] == "active":
                u["status"] = "expired"
                changed = True

            # چک انقضا
            if u.get("expire_at"):
                try:
                    if datetime.fromisoformat(u["expire_at"]) < datetime.now():
                        if u["status"] == "active":
                            u["status"] = "expired"
                            changed = True
                except:
                    pass

        if changed:
            self.save()

        return self.db["users"]


# ==================== SINGLETON ====================
xray_core = XrayCore()
user_manager = UserManager(xray_core)


# ==================== AUTO MONITOR THREAD ====================
def monitor_loop():
    """هر ۶۰ ثانیه آمار رو آپدیت کن"""
    while True:
        try:
            user_manager.update_usage()
        except Exception as e:
            print(f"[monitor] error: {e}")
        time.sleep(60)


def start_monitor():
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()


if __name__ == "__main__":
    print("🔥 APEX Server Manager")
    print("Testing Xray...")
    ok, msg = xray_core.start()
    print(f"Start: {msg}")
    if ok:
        time.sleep(2)
        print(f"Running: {xray_core.is_running()}")
        print(f"Stats: {xray_core.get_stats()}")
