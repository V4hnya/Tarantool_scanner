<img width="700" alt="Tarantool_scanner" src="https://github.com/user-attachments/assets/be42abdc-9889-40e6-9e18-088cbefac448" />
# Tarantool_scanner

`Tarantool_scanner` is a lightweight security scanner for Tarantool environments. The project combines:

- HTTP checks for Tarantool Cartridge admin panels and GraphQL endpoints
- IPROTO checks through a Lua script executed by the `tarantool` runtime
- weak credential checks
- several unsafe exposure checks
- basic version-based risk hints for known Tarantool issue classes


## Features

### HTTP / Cartridge checks

The Python scanner probes common Cartridge and HTTP management ports:

- `8080`
- `8091`
- `8092`
- `8190`

It can:

- detect a Tarantool Cartridge admin panel at `/admin`
- check common unauthenticated info endpoints:
  - `/metrics`
  - `/metrics/prometheus`
  - `/health`
  - `/swagger`
  - `/api/swagger.json`
- test several admin paths for possible auth bypass behavior:
  - `/admin/cluster/`
  - `/admin/cluster/dashboard`
  - `/admin/cluster/topology`
- inspect JavaScript loaded by the admin page and extract role-like keywords
- test GraphQL exposure on `/api/graphql`
- brute-force GraphQL login using a small default credential set or custom dictionaries

### Binary IPROTO checks

For native Tarantool ports, the Python launcher delegates to the Lua scanner. By default the binary protocol target port is:

- `3301`

The Lua script performs:

- TCP reachability check
- Tarantool version extraction from the greeting banner
- coarse risk labeling based on the detected version
- slow-session / dead-session behavior check
- malformed IPROTO packet checks
- guest access check
- safe reads from system spaces when guest access is available:
  - `_vuser`
  - `_vpriv`
- password brute-force for a chosen Tarantool user

## Requirements

### Python

- Python 3.8+
- `requests`
- `urllib3`

Install dependencies:

```bash
pip install -r requirements.txt
```

### Tarantool runtime

The Lua scanner is executed through the `tarantool` binary, so Tarantool must be installed locally and available in `PATH`.

Quick check:

```bash
tarantool --version
```

If `tarantool` is not installed, IPROTO checks will not work.

## How it works

`Tarantool_scanner.py` acts as the main entry point.

Scanning logic:

1. Load targets from a single IP or an IP list.
2. Probe selected ports.
3. For Cartridge ports, try HTTP first.
4. For port `3301`, run the Lua IPROTO scanner.
5. For custom ports, try HTTP first and then fall back to IPROTO.

The Python script automatically invokes:

```bash
tarantool script.lua -i <host:port>
```

and parses the Lua output into a unified report.

## Usage

### Scan a single host with default ports

```bash
python3 Tarantool_scanner.py -i 192.0.2.10
```

### Scan a list of hosts

```bash
python3 Tarantool_scanner.py -I hosts.txt
```

### Scan custom ports

```bash
python3 Tarantool_scanner.py -i 192.0.2.10 -p 8080 8091 3301 8081
```

### Use custom HTTP usernames and passwords

```bash
python3 Tarantool_scanner.py \
  -i 192.0.2.10 \
  --http-user-file users.txt \
  --http-pass-file passwords.txt
```

### Use a custom IPROTO password list

```bash
python3 Tarantool_scanner.py \
  -i 192.0.2.10 \
  --iproto-user admin \
  --iproto-pass-file iproto_passwords.txt
```

## Python CLI options

```text
usage: Tarantool_scanner.py [-h] (-i IP | -I IP_FILE) [-p PORTS [PORTS ...]]
                            [--http-user-file HTTP_USER_FILE]
                            [--http-pass-file HTTP_PASS_FILE]
                            [--iproto-user IPROTO_USER]
                            [--iproto-pass-file IPROTO_PASS_FILE]
```

Options:

- `-i`, `--ip` — scan a single IP address
- `-I`, `--ip-file` — scan IPs from a file
- `-p`, `--ports` — ports to scan
- `--http-user-file` — file with usernames for HTTP/GraphQL brute-force
- `--http-pass-file` — file with passwords for HTTP/GraphQL brute-force
- `--iproto-user` — Tarantool username for IPROTO brute-force
- `--iproto-pass-file` — password file for IPROTO brute-force

Scanner using default credentials

## Example output

```text
############################################################
REPORT FOR 192.0.2.10:8080 [HTTP CARTRIDGE]
############################################################
  [!] Tarantool Cartridge panel detected (HTTP 200, 6421 bytes)
  [*] GraphQL API protected, requires session
  [*] Brute-forcing GraphQL with 8 credential pairs...
  [-] No valid credentials found in supplied list
```

```text
========================================
[+] РЕЗУЛЬТАТ ДЛЯ 192.0.2.10:3301
========================================
  [v] ВЕРСИЯ: 2.11.0 -> MEDIUM (2.11.0): Известны логические баги парсинга IPROTO, DateTime-баг CVE-2025-6536.
  [✓] Гостевой доступ заблокирован/требует пароль.
  [*] Запуск брутфорса для пользователя 'admin'...
  [-] Брутфорс завершен. Валидных паролей не найдено.
```

## Safety and legal notice

Use this project only against systems you own or are explicitly authorized to test.

The scanner performs:

- authentication attempts
- brute-force style password checks with small dictionaries
- malformed packet checks against IPROTO services

Running it against third-party infrastructure without permission may be illegal and may disrupt services.

## Improvement ideas

Possible next steps for the project:

- add structured output formats such as JSON
- add concurrency controls and rate limiting
- separate detection, brute-force, and destructive-risk checks into modes
- add TLS options and proxy support
- support CIDR/range input
- improve result normalization between Python and Lua stages
- add tests and sample targets

## License

No license file is currently present in the repository. Until a license is added, reuse terms are not explicitly defined.
