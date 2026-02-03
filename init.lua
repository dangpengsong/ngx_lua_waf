-- 缓存全局 API
local ngx      = ngx
local ngx_find = ngx.re.find
local insert   = table.insert
local lower    = string.lower
local match    = string.match
local gsub     = string.gsub
local fmt      = string.format
local tonumber = tonumber
local type     = type
local ipairs   = ipairs
local pairs    = pairs
-- 加载配置
require 'config'
local rule_path = gsub(rulepath, "/+$", "")
local log_path  = gsub(logdir, "/+$", "")
-- 辅助工具:将数组转换为 Hash 表提升查询速度
local function to_hash(list)
    local t = {}
    if list then
        for _, v in ipairs(list) do t[v] = true end
    end
    return t
end
-- 配置初始化
local function is_on(opt) return opt == "on" end
local redirect_on   = is_on(redirect)
local attack_log_on = is_on(attacklog)
local white_on      = is_on(white_module)
local url_deny_on   = is_on(url_deny)
local cookie_on     = is_on(cookie_match)
local cc_deny_on    = is_on(cc_deny)
-- 预转换 IP 列表为 Hash 结构
local ip_white_hash = to_hash(ipWhitelist)
local ip_block_hash = to_hash(ipBlocklist)
-- ---------------------------------------------------------
-- 内部工具函数
-- ---------------------------------------------------------
local function get_client_ip()
    return ngx.var.remote_addr or "unknown"
end

-- 多重 URL 解码（防止双重/多重编码绕过）
local function multi_unescape(str, max_rounds)
    if not str or str == "" then return str end
    max_rounds = max_rounds or 3
    local decoded = str
    for i = 1, max_rounds do
        local new_decoded = ngx.unescape_uri(decoded)
        if new_decoded == decoded then
            break -- 没有变化，停止解码
        end
        decoded = new_decoded
    end
    return decoded
end

-- 解码并标准化输入（统一处理各种绕过技术）
local function normalize_input(str)
    if not str or str == "" then return str end
    if type(str) ~= "string" then return tostring(str) end
    -- 1. 多重 URL 解码
    local decoded = multi_unescape(str, 3)
    -- 2. 移除 SQL 注释混淆 (/*...*/)
    decoded = gsub(decoded, "/%*.-%*/", " ")
    return decoded
end
local function write_log(method, url, data, rule_tag)
    if not attack_log_on then return end
    local ip      = get_client_ip()
    local host    = ngx.var.server_name or "localhost"
    local time    = ngx.localtime()
    local ua      = ngx.var.http_user_agent or "-"
    local log_file = fmt("%s/%s_%s_sec.log", log_path, host, ngx.today())
    local message  = fmt("%s [%s] %s %s%s \"%s\" \"%s\" \"%s\"\n",
                         ip, time, method, host, url, data, rule_tag, ua)
    ngx.timer.at(0, function(premature)
        if premature then return end
        local fd, err = io.open(log_file, "ab")
        if fd then
            fd:write(message)
            fd:close()
        else
            ngx.log(ngx.ERR, "WAF log write failed: ", err)
        end
    end)
end
-- 统一拦截入口
local function do_action(method, url, data, rule)
    write_log(method, url, data, rule) -- 记录日志
    if redirect_on then
        ngx.header.content_type = "text/html"
        ngx.status = 403 -- 统一返回 403 状态码
        ngx.say(html or "Blocked by WAF")    -- 输出 config.lua 里的 HTML 变量
        ngx.exit(ngx.status) -- 终止请求
    end
    return true
end
local function load_rules(filename)
    local path = rule_path .. '/' .. filename
    local file, err = io.open(path, "r")
    if not file then
        ngx.log(ngx.WARN, "WAF rule file not found: ", path, " - ", err or "unknown")
        return nil
    end
    local t = {}
    for line in file:lines() do
        -- 跳过空行和注释行（以#开头）
        local trimmed = match(line, "^%s*(.-)%s*$") or ""
        if trimmed ~= "" and not match(trimmed, "^#") then
            insert(t, trimmed)
        end
    end
    file:close()
    if #t > 0 then
        ngx.log(ngx.NOTICE, "WAF loaded ", #t, " rules from: ", filename)
    end
    return #t > 0 and t or nil
end
-- 规则库
local rules = {
    url   = load_rules('url'),
    args  = load_rules('args'),
    ua    = load_rules('user-agent'),
    white = load_rules('whiteurl'),
    post  = load_rules('post'),
    ck    = load_rules('cookie')
}
-- ---------------------------------------------------------
-- 导出给 waf.lua 使用的检测模块
-- ---------------------------------------------------------
function check_ip_white()
    return ip_white_hash[get_client_ip()]
end
function check_ip_block()
    if ip_block_hash[get_client_ip()] then
        return do_action('IP', ngx.var.request_uri, "-", "IP Blocklist Match")
    end
    return false
end
function check_white_url()
    if white_on and rules.white then
        for _, rule in ipairs(rules.white) do
            if ngx_find(ngx.var.uri, rule, "isjo") then return true end
        end
    end
    return false
end
function check_cc()
    if not cc_deny_on then return false end
    local limit = ngx.shared.limit
    if not limit then
        ngx.log(ngx.ERR, "WAF CC: shared dict 'limit' not configured")
        return false
    end
    local count, sec = match(cc_rate, "(%d+)/(%d+)")
    if not count or not sec then return false end
    count, sec = tonumber(count), tonumber(sec)
    local token = get_client_ip() .. ngx.var.uri
    local req, _ = limit:get(token)
    if req then
        if req > count then
            return do_action('CC', ngx.var.request_uri, "-", fmt("CC Attack: %dreq/%ds", count, sec))
        end
        -- incr 可能在 key 过期后失败，需要处理
        local new_val, err = limit:incr(token, 1)
        if not new_val then
            limit:set(token, 1, sec)
        end
    else
        limit:set(token, 1, sec)
    end
    return false
end
function check_ua()
    local ua = ngx.var.http_user_agent
    if ua and rules.ua then
        for _, rule in ipairs(rules.ua) do
            if ngx_find(ua, rule, "isjo") then
                return do_action('UA', ngx.var.request_uri, ua, rule)
            end
        end
    end
    return false
end
function check_url()
    if url_deny_on and rules.url then
        for _, rule in ipairs(rules.url) do
            if ngx_find(ngx.var.request_uri, rule, "isjo") then
                return do_action('URL', ngx.var.request_uri, "-", rule)
            end
        end
    end
    return false
end
function check_args()
    local query_args = ngx.req.get_uri_args()
    if not query_args or not rules.args then return false end
    for key, val in pairs(query_args) do
        -- 检测参数名
        local norm_key = normalize_input(key)
        for _, rule in ipairs(rules.args) do
            if ngx_find(norm_key, rule, "isjo") then
                return do_action('GET', ngx.var.request_uri, key, rule)
            end
        end
        -- 检测参数值（支持数组参数）
        local values = type(val) == "table" and val or {val}
        for _, v in ipairs(values) do
            if v and v ~= true then
                local norm_val = normalize_input(v)
                for _, rule in ipairs(rules.args) do
                    if ngx_find(norm_val, rule, "isjo") then
                        return do_action('GET', ngx.var.request_uri, v, rule)
                    end
                end
            end
        end
    end
    return false
end
function check_cookie()
    local ck = ngx.var.http_cookie
    if cookie_on and ck and rules.ck then
        local norm_ck = normalize_input(ck)
        for _, rule in ipairs(rules.ck) do
            if ngx_find(norm_ck, rule, "isjo") then
                return do_action('Cookie', ngx.var.request_uri, ck, rule)
            end
        end
    end
    return false
end
function check_headers()
    local headers = ngx.req.get_headers()
    if not headers or not rules.args then return false end
    -- 需要特别检测的头部（Log4j JNDI 等攻击常通过这些头部注入）
    local sensitive_headers = {
        "user-agent", "referer", "x-forwarded-for", "x-real-ip",
        "x-api-version", "x-requested-with", "accept-language",
        "authorization", "cookie", "origin"
    }
    for key, val in pairs(headers) do
        local data = type(val) == "table" and table.concat(val, " ") or val
        if data and type(data) == "string" then
            local norm_data = normalize_input(data)
            for _, rule in ipairs(rules.args) do
                if ngx_find(norm_data, rule, "isjo") then
                    return do_action('HEADER', ngx.var.request_uri, data, "Header Attack: " .. key)
                end
            end
        end
    end
    return false
end
function check_body(data)
    if rules.post and data and data ~= "" then
        local norm_data = normalize_input(data)
        for _, rule in ipairs(rules.post) do
            if ngx_find(norm_data, rule, "isjo") then
                return do_action('POST', ngx.var.request_uri, data, rule)
            end
        end
    end
    return false
end
function check_file_ext(ext)
    if not ext then return false end
    for _, rule in ipairs(black_fileext) do
        if ngx_find(lower(ext), rule, "isjo") then
            return do_action('UPLOAD', ngx.var.request_uri, ext, "Blocked File Ext: " .. ext)
        end
    end
    return false
end

-- 导出 do_action 供 waf.lua 使用
function waf_action(method, url, data, rule)
    return do_action(method, url, data, rule)
end

-- 检测异常 HTTP 方法
function check_http_method()
    local method = ngx.req.get_method()
    local allowed = {GET=true, POST=true, HEAD=true, OPTIONS=true, PUT=true, DELETE=true, PATCH=true}
    if not allowed[method] then
        return do_action('METHOD', ngx.var.request_uri, method, "Invalid HTTP Method: " .. method)
    end
    return false
end

-- 检测 Host 头异常
function check_host_header()
    local host = ngx.var.http_host
    if not host or host == "" then
        return do_action('HOST', ngx.var.request_uri, "-", "Missing Host Header")
    end
    -- 检测 Host 头注入攻击
    if ngx_find(host, "[\r\n]", "jo") then
        return do_action('HOST', ngx.var.request_uri, host, "Host Header Injection")
    end
    return false
end

-- 检测 Referer 异常
function check_referer()
    local referer = ngx.var.http_referer
    if referer and rules.args then
        for _, rule in ipairs(rules.args) do
            if ngx_find(referer, rule, "isjo") then
                return do_action('Referer', ngx.var.request_uri, referer, rule)
            end
        end
    end
    return false
end