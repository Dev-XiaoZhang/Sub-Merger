import base64
import ipaddress
import os
import sqlite3
import secrets
import urllib.parse
from datetime import datetime
from functools import wraps
from pathlib import Path

import requests
import yaml
from flask import Flask, Response, jsonify, redirect, render_template, request, session

BASE_DIR = Path(__file__).parent
DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "sub-merger.db"

app = Flask(__name__)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
app.secret_key = f"sub-merger:{ADMIN_PASSWORD}"
MODE = os.getenv("SERVER_MODE", "admin")


def db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with db() as connection:
        connection.executescript("""
        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'vmess',
            server TEXT NOT NULL DEFAULT '',
            port TEXT NOT NULL DEFAULT '',
            config TEXT NOT NULL DEFAULT '{}',
            source TEXT NOT NULL DEFAULT 'manual',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            node_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            client_type TEXT NOT NULL,
            requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        INSERT OR IGNORE INTO settings(key, value) VALUES ('subscription_token', '');
        INSERT OR IGNORE INTO settings(key, value) VALUES ('subscription_name', 'Sub-Merger');
        """)
        token = connection.execute("SELECT value FROM settings WHERE key='subscription_token'").fetchone()["value"]
        if not token:
            connection.execute("UPDATE settings SET value=? WHERE key='subscription_token'", (secrets.token_urlsafe(24),))


init_db()


def normalize_legacy_uri_names():
    uri_schemes = ("ss://", "vmess://", "vless://", "trojan://", "socks5://", "hysteria://", "hysteria2://", "hy2://", "tuic://", "wireguard://")
    counter = 0
    with db() as connection:
        rows = connection.execute("SELECT id, name, config FROM nodes").fetchall()
        for row in rows:
            if row["name"] and row["name"].lower().startswith(uri_schemes):
                counter += 1
                proxy = yaml.safe_load(row["config"])
                uri = proxy.get("uri", "") if isinstance(proxy, dict) else ""
                fragment = urllib.parse.unquote(uri.partition("#")[2]).strip() if uri else ""
                scheme = uri.partition(":")[0].upper() if uri else "NODE"
                new_name = fragment or f"{scheme} 节点 {counter}"
                if isinstance(proxy, dict):
                    proxy["name"] = new_name
                    connection.execute("UPDATE nodes SET name=?, config=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (new_name, yaml.safe_dump(proxy, allow_unicode=True), row["id"]))
                else:
                    connection.execute("UPDATE nodes SET name=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (new_name, row["id"]))


normalize_legacy_uri_names()


@app.before_request
def restrict_subscription_server():
    if MODE == "subscription" and request.path != "/":
        return "Not found", 404


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            return redirect("/login")
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/")
        return render_template("login.html", error="管理密码错误"), 401
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


def current_token():
    with db() as connection:
        return connection.execute("SELECT value FROM settings WHERE key='subscription_token'").fetchone()["value"]


def public_ip():
    candidate = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Real-IP")
    if not candidate:
        forwarded = request.headers.get("X-Forwarded-For", "")
        candidate = forwarded.split(",", 1)[0].strip() if forwarded else request.remote_addr
    try:
        address = ipaddress.ip_address(candidate)
        if address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            return None
        return str(address)
    except ValueError:
        return None


def client_type(user_agent):
    ua = (user_agent or "").lower()
    if "shadowrocket" in ua:
        return "Shadowrocket"
    if "mihomo" in ua or "meta" in ua:
        return "mihomo"
    if "clash" in ua:
        return "Clash"
    if "surge" in ua:
        return "Surge"
    return "Unknown"


def parse_proxy_payload(content):
    try:
        content = base64.b64decode(content.strip(), validate=True).decode("utf-8")
    except Exception:
        pass
    try:
        parsed = yaml.safe_load(content)
    except yaml.YAMLError:
        parsed = None
    if isinstance(parsed, dict) and isinstance(parsed.get("proxies"), list):
        return parsed["proxies"]
    proxies = []
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            scheme = line.split(":", 1)[0].lower() if ":" in line else ""
            if scheme in {"ss", "vmess", "vless", "trojan", "socks5", "hysteria", "hysteria2", "hy2", "tuic", "wireguard"}:
                fragment = urllib.parse.unquote(line.partition("#")[2]).strip()
                uri_name = fragment or f"{scheme.upper()} 节点 {len(proxies) + 1}"
                if scheme == "vless":
                    proxies.append(parse_vless_uri(line, uri_name))
                elif scheme == "trojan":
                    proxies.append(parse_trojan_uri(line, uri_name))
                else:
                    proxies.append({"uri": line, "name": uri_name, "type": scheme})
    return proxies


def parse_vless_uri(uri, name):
    parsed = urllib.parse.urlparse(uri)
    query = urllib.parse.parse_qs(parsed.query)
    value = lambda key, default=None: query.get(key, [default])[0]
    proxy = {
        "name": name,
        "type": "vless",
        "server": parsed.hostname or "",
        "port": parsed.port or 443,
        "uuid": urllib.parse.unquote(parsed.username or ""),
        "udp": True,
        "tls": value("security") in {"tls", "reality"},
        "network": value("type", "tcp"),
        "flow": value("flow", ""),
    }
    if proxy["network"] == "ws":
        proxy["ws-opts"] = {"path": value("path", "/"), "headers": {"Host": value("host", parsed.hostname or "")}}
    elif proxy["network"] == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": value("serviceName", "")}
    if value("security") == "tls":
        proxy["servername"] = value("sni", parsed.hostname or "")
        proxy["client-fingerprint"] = value("fp", "chrome")
    if value("security") == "reality":
        proxy.update({
            "servername": value("sni", parsed.hostname or ""),
            "client-fingerprint": value("fp", "chrome"),
            "reality-opts": {"public-key": value("pbk", ""), "short-id": value("sid", "")},
        })
    return proxy


def parse_trojan_uri(uri, name):
    parsed = urllib.parse.urlparse(uri)
    query = urllib.parse.parse_qs(parsed.query)
    value = lambda key, default=None: query.get(key, [default])[0]
    proxy = {
        "name": name,
        "type": "trojan",
        "server": parsed.hostname or "",
        "port": parsed.port or 443,
        "password": urllib.parse.unquote(parsed.username or ""),
        "udp": True,
        "sni": value("sni", parsed.hostname or ""),
        "skip-cert-verify": value("allowInsecure", "false") == "true",
        "network": value("type", "tcp"),
    }
    if proxy["network"] == "ws":
        proxy["ws-opts"] = {"path": value("path", "/"), "headers": {"Host": value("host", parsed.hostname or "")}}
    return proxy


def safe_http_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("仅支持 HTTP/HTTPS 上游链接")
    try:
        addresses = {str(ipaddress.ip_address(parsed.hostname))}
    except ValueError:
        addresses = set()
    if addresses and any(ipaddress.ip_address(address).is_private for address in addresses):
        raise ValueError("不允许导入内网地址")
    return url


@app.route("/")
def dashboard():
    token = request.args.get("token")
    if token:
        return serve_subscription_from_root(token)
    if MODE == "subscription":
        return "Subscription token required", 400
    if not session.get("admin"):
        return redirect("/login")
    with db() as connection:
        nodes = [dict(node) for node in connection.execute("SELECT * FROM nodes ORDER BY id DESC")]
        source_names = {f"subscription:{row['id']}": row["name"] for row in connection.execute("SELECT id, name FROM subscriptions")}
        for node in nodes:
            node["source_name"] = "手动节点" if node["source"] == "manual" else source_names.get(node["source"], "未知订阅")
        sources = [dict(source) for source in connection.execute("SELECT * FROM subscriptions ORDER BY id DESC")]
        for source in sources:
            source["node_count"] = connection.execute("SELECT COUNT(*) FROM nodes WHERE source=?", (f"subscription:{source['id']}",)).fetchone()[0]
        logs = connection.execute("SELECT * FROM access_logs ORDER BY id DESC LIMIT 10").fetchall()
        token = connection.execute("SELECT value FROM settings WHERE key='subscription_token'").fetchone()["value"]
        name = connection.execute("SELECT value FROM settings WHERE key='subscription_name'").fetchone()["value"]
    return render_template("admin.html", nodes=nodes, sources=sources, logs=logs, token=token, subscription_name=name)


@app.post("/api/sources")
@admin_required
def add_source():
    data = request.get_json(silent=True) or request.form
    url = (data.get("url") or "").strip()
    name = (data.get("name") or "未命名订阅").strip()
    if not url:
        return jsonify(error="请输入订阅链接"), 400
    try:
        safe_http_url(url)
    except ValueError as error:
        return jsonify(error=str(error)), 400
    try:
        response = requests.get(url, timeout=20, headers={"User-Agent": "Sub-Merger/1.0"})
        response.raise_for_status()
        proxies = parse_proxy_payload(response.text)
    except Exception as error:
        return jsonify(error=f"订阅拉取失败：{error}"), 400
    with db() as connection:
        cursor = connection.execute("INSERT INTO subscriptions(name, url, node_count) VALUES (?, ?, ?)", (name, url, len(proxies)))
        source_id = cursor.lastrowid
        for proxy in proxies:
            proxy_name = proxy.get("name") or f"节点 {source_id}-{len(proxy) and source_id}"
            connection.execute(
                "INSERT INTO nodes(name, type, server, port, config, source) VALUES (?, ?, ?, ?, ?, ?)",
                (str(proxy_name), str(proxy.get("type", "unknown")), str(proxy.get("server", "")), str(proxy.get("port", "")), yaml.safe_dump(proxy, allow_unicode=True), f"subscription:{source_id}"),
            )
    return jsonify(ok=True, count=len(proxies))


@app.post("/api/sources/<int:source_id>")
@admin_required
def edit_source(source_id):
    data = request.get_json(silent=True) or request.form
    name = (data.get("name") or "未命名订阅").strip()
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify(error="请输入订阅链接"), 400
    try:
        safe_http_url(url)
        response = requests.get(url, timeout=20, headers={"User-Agent": "Sub-Merger/1.0"})
        response.raise_for_status()
        proxies = parse_proxy_payload(response.text)
    except Exception as error:
        return jsonify(error=f"订阅更新失败：{error}"), 400
    with db() as connection:
        if not connection.execute("SELECT 1 FROM subscriptions WHERE id=?", (source_id,)).fetchone():
            return jsonify(error="订阅不存在"), 404
        connection.execute("UPDATE subscriptions SET name=?, url=?, node_count=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (name, url, len(proxies), source_id))
        source_key = f"subscription:{source_id}"
        connection.execute("DELETE FROM nodes WHERE source=?", (source_key,))
        for proxy in proxies:
            proxy_name = proxy.get("name") or "未命名节点"
            connection.execute(
                "INSERT INTO nodes(name, type, server, port, config, source) VALUES (?, ?, ?, ?, ?, ?)",
                (str(proxy_name), str(proxy.get("type", "unknown")), str(proxy.get("server", "")), str(proxy.get("port", "")), yaml.safe_dump(proxy, allow_unicode=True), source_key),
            )
    return jsonify(ok=True, count=len(proxies))


@app.delete("/api/sources/<int:source_id>")
@admin_required
def delete_source(source_id):
    with db() as connection:
        connection.execute("DELETE FROM subscriptions WHERE id=?", (source_id,))
        connection.execute("DELETE FROM nodes WHERE source=?", (f"subscription:{source_id}",))
    return jsonify(ok=True)


@app.post("/api/sources/<int:source_id>/refresh")
@admin_required
def refresh_source(source_id):
    with db() as connection:
        source = connection.execute("SELECT * FROM subscriptions WHERE id=?", (source_id,)).fetchone()
    if not source:
        return jsonify(error="订阅不存在"), 404
    try:
        response = requests.get(source["url"], timeout=20, headers={"User-Agent": "Sub-Merger/1.0"})
        response.raise_for_status()
        proxies = parse_proxy_payload(response.text)
    except Exception as error:
        return jsonify(error=f"订阅拉取失败：{error}"), 400
    with db() as connection:
        connection.execute("DELETE FROM nodes WHERE source=?", (f"subscription:{source_id}",))
        for proxy in proxies:
            connection.execute(
                "INSERT INTO nodes(name, type, server, port, config, source) VALUES (?, ?, ?, ?, ?, ?)",
                (str(proxy.get("name") or "未命名节点"), str(proxy.get("type", "unknown")), str(proxy.get("server", "")), str(proxy.get("port", "")), yaml.safe_dump(proxy, allow_unicode=True), f"subscription:{source_id}"),
            )
        connection.execute("UPDATE subscriptions SET node_count=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (len(proxies), source_id))
    return jsonify(ok=True, count=len(proxies))


@app.post("/api/nodes")
@admin_required
def add_node():
    data = request.get_json(silent=True) or request.form
    try:
        config = yaml.safe_load(data.get("config", "{}"))
        if not isinstance(config, dict):
            raise ValueError
        name = config.get("name") or data.get("name")
        if not name:
            raise ValueError("节点名称不能为空")
    except Exception as error:
        return jsonify(error=f"节点配置无效：{error}"), 400
    with db() as connection:
        if data.get("name"):
            name = str(data.get("name")).strip()
            config["name"] = name
        connection.execute(
            "INSERT INTO nodes(name, type, server, port, config, source) VALUES (?, ?, ?, ?, ?, 'manual')",
            (str(name), str(config.get("type", "unknown")), str(config.get("server", "")), str(config.get("port", "")), yaml.safe_dump(config, allow_unicode=True)),
        )
    return jsonify(ok=True)


@app.delete("/api/nodes/<int:node_id>")
@admin_required
def delete_node(node_id):
    with db() as connection:
        connection.execute("DELETE FROM nodes WHERE id=?", (node_id,))
    return jsonify(ok=True)


@app.post("/api/nodes/<int:node_id>")
@admin_required
def edit_node(node_id):
    data = request.get_json(silent=True) or request.form
    try:
        config = yaml.safe_load(data.get("config", "{}"))
        if not isinstance(config, dict):
            raise ValueError
        name = config.get("name") or data.get("name")
        if not name:
            raise ValueError("节点名称不能为空")
    except Exception as error:
        return jsonify(error=f"节点配置无效：{error}"), 400
    with db() as connection:
        if not connection.execute("SELECT 1 FROM nodes WHERE id=?", (node_id,)).fetchone():
            return jsonify(error="节点不存在"), 404
        if data.get("name"):
            config["name"] = str(data.get("name")).strip()
            name = config["name"]
        connection.execute(
            "UPDATE nodes SET name=?, type=?, server=?, port=?, config=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (str(name), str(config.get("type", "unknown")), str(config.get("server", "")), str(config.get("port", "")), yaml.safe_dump(config, allow_unicode=True), node_id),
        )
    return jsonify(ok=True)


@app.post("/api/token/reset")
@admin_required
def reset_token():
    token = secrets.token_urlsafe(24)
    with db() as connection:
        connection.execute("UPDATE settings SET value=? WHERE key='subscription_token'", (token,))
    return jsonify(ok=True, token=token)


@app.post("/api/settings")
@admin_required
def save_settings():
    data = request.get_json(silent=True) or request.form
    name = (data.get("name") or "Sub-Merger").strip()
    with db() as connection:
        connection.execute("UPDATE settings SET value=? WHERE key='subscription_name'", (name,))
    return jsonify(ok=True)


def subscription_document(token):
    with db() as connection:
        rows = connection.execute("SELECT name, config, source FROM nodes ORDER BY id ASC").fetchall()
        source_names = {f"subscription:{row['id']}": row["name"] for row in connection.execute("SELECT id, name FROM subscriptions")}
        name = connection.execute("SELECT value FROM settings WHERE key='subscription_name'").fetchone()["value"]
    proxies = []
    seen = set()
    for row in rows:
        try:
            proxy = yaml.safe_load(row["config"])
        except yaml.YAMLError:
            continue
        if isinstance(proxy, dict) and proxy.get("uri") and proxy.get("type") == "vless":
            proxy = parse_vless_uri(proxy["uri"], str(row["name"]))
        elif isinstance(proxy, dict) and proxy.get("uri") and proxy.get("type") == "trojan":
            proxy = parse_trojan_uri(proxy["uri"], str(row["name"]))
        if isinstance(proxy, dict) and proxy.get("type"):
            proxy["name"] = str(row["name"])
            base_name = str(proxy["name"])
            candidate = base_name
            suffix = 2
            while candidate in seen:
                candidate = f"{base_name}-{suffix}"
                suffix += 1
            proxy["name"] = candidate
            seen.add(candidate)
            proxies.append(proxy)
    document = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "global",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [{"name": name, "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50, "proxies": [proxy["name"] for proxy in proxies]}],
    }
    return f"# {name}\n# Subscription token: {token}\n" + yaml.safe_dump(document, allow_unicode=True, sort_keys=False)


def serve_subscription_from_root(token):
    expected = current_token()
    if not secrets.compare_digest(token, expected):
        return "Invalid subscription token", 404
    address = public_ip()
    if address:
        with db() as connection:
            connection.execute("INSERT INTO access_logs(ip, user_agent, client_type) VALUES (?, ?, ?)", (address, request.headers.get("User-Agent", "")[:500], client_type(request.headers.get("User-Agent", ""))))
    return Response(subscription_document(token), content_type="text/yaml; charset=utf-8", headers={"Subscription-Userinfo": "upload=0; download=0; total=0; expire=0", "Profile-Update-Interval": "24"})


if __name__ == "__main__":
    port = 8081 if MODE == "subscription" else 8080
    app.run(host="0.0.0.0", port=port)
