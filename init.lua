-- 缓存全局 API
local ngx      = ngx
local ngx_find = ngx.re.find
local insert   = table.insert
local lower    = string.lower
-- 加载配置
require 'config'
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
local rule_path     = rulepath
local log_path      = logdir
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
local function write_log(method, url, data, rule_tag)
    if not attack_log_on then return end
    local ip      = get_client_ip()
    local host    = ngx.var.server_name or "localhost"
    local time    = ngx.localtime()
    local log_file = string.format("%s/%s_%s_sec.log", log_path, host, ngx.today())
    local message  = string.format("%s [%s] %s %s%s \"%s\" \"%s\"\n",
                                   ip, time, method, host, url, data, rule_tag)
    ngx.timer.at(0, function()
        local fd = io.open(log_file, "ab")
        if fd then
            fd:write(message)
            fd:close()
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
    local file = io.open(path, "r")
    if not file then return nil end
    local t = {}
    for line in file:lines() do
        if line ~= "" then insert(t, line) end
    end
    file:close()
    return t
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
    if not limit then return false end
    local count, sec = string.match(cc_rate, "(%d+)/(%d+)")
    local token = get_client_ip() .. ngx.var.uri
    local req, _ = limit:get(token)
    if req and req > tonumber(count) then
        return do_action('CC', ngx.var.request_uri, "-", "CC Attack: "..count.."req/"..sec.."s")
    elseif req then
        limit:incr(token, 1)
    else
        limit:set(token, 1, tonumber(sec))
    end
    return false
end
function check_ua()
    local ua = ngx.var.http_user_agent
    if ua and rules.ua then
        for _, rule in ipairs(rules.ua) do
            if ngx_find(ua, rule, "isjo") then
                return do_action('UA', ngx.var.request_uri, "-", rule)
            end
        end
    end
end
function check_url()
    if url_deny_on and rules.url then
        for _, rule in ipairs(rules.url) do
            if ngx_find(ngx.var.request_uri, rule, "isjo") then
                return do_action('GET', ngx.var.request_uri, "-", rule)
            end
        end
    end
end
function check_args()
    local query_args = ngx.req.get_uri_args()
    if not query_args or not rules.args then return false end
    for _, rule in ipairs(rules.args) do
        for _, val in pairs(query_args) do
            local data = type(val) == "table" and table.concat(val, " ") or val
            if data and data ~= true then
                if ngx_find(ngx.unescape_uri(data), rule, "isjo") then
                    return do_action('GET', ngx.var.request_uri, "-", rule)
                end
            end
        end
    end
end
function check_cookie()
    local ck = ngx.var.http_cookie
    if cookie_on and ck and rules.ck then
        for _, rule in ipairs(rules.ck) do
            if ngx_find(ck, rule, "isjo") then
                return do_action('Cookie', ngx.var.request_uri, "-", rule)
            end
        end
    end
end
function check_body(data)
    if rules.post and data ~= "" then
        for _, rule in ipairs(rules.post) do
            if ngx_find(ngx.unescape_uri(data), rule, "isjo") then
                return do_action('POST', ngx.var.request_uri, "-", rule)
            end
        end
    end
    return false
end
function check_file_ext(ext)
    if not ext then return false end
    for _, rule in ipairs(black_fileext) do
        if ngx_find(lower(ext), rule, "isjo") then
            return do_action('POST', ngx.var.request_uri, "-", "File Ext Attack: "..ext)
        end
    end
end