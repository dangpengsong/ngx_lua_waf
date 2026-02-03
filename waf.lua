-- =============================================================================
-- WAF 主入口（带错误保护）
-- 原则：出错时默认阻止请求（安全优先）
-- =============================================================================
local var = ngx.var
local req = ngx.req
local find = string.find
local match = string.match
local min = math.min

-- 核心检测逻辑（用 pcall 包装）
local function waf_check()
    -- 1. IP 级别防护(最高优先级)
    if check_ip_white() then return "pass", "IP Whitelist" end
    if check_ip_block() then return "block", "IP Blocklist" end

    -- 2. 基础识别与 CC 防护
    if check_white_url() then return "pass", "URL Whitelist" end
    if check_cc() then return "block", "CC Attack" end

    -- 2.5 HTTP 方法与 Host 头校验
    if check_http_method() then return "block", "Invalid Method" end
    if check_host_header() then return "block", "Invalid Host" end

    -- 3. 扫描器指纹硬拦截(扩展检测)
    if var.http_Acunetix_Aspect or var.http_X_Scan_Memo or
       var.http_X_Forwarded_Host or var.http_X_Client_IP or
       var.http_X_Wap_Profile or var.http_X_Arbitrary or
       var.http_X_ATT_DeviceId then
        waf_action('SCANNER', var.request_uri, "-", "Scanner Fingerprint")
        return "block", "Scanner"
    end

    -- 4. 静态特征检测 (UA/URL/Args/Cookie/Headers/Referer)
    if check_ua() then return "block", "UA" end
    if check_url() then return "block", "URL" end
    if check_args() then return "block", "Args" end
    if check_cookie() then return "block", "Cookie" end
    if check_headers() then return "block", "Headers" end
    if check_referer() then return "block", "Referer" end

    -- 5. POST 深度检测 (检查配置变量 post_match)
    if post_match == "on" and req.get_method() == "POST" then
        local content_type = var.content_type or ""
        local content_length = tonumber(var.content_length) or 0
        
        -- 请求体大小限制（10MB）
        local max_body_size = 10 * 1024 * 1024
        if content_length > max_body_size then
            waf_action('POST', var.request_uri, "-", "Request body too large: " .. content_length)
            return "block", "Body Size"
        end
        
        -- Multipart 分块处理
        if find(content_type, "multipart/form-data", 1, true) then
            local sock, err = req.socket()
            if not sock then return "pass", "No Socket" end
            req.init_body(128 * 1024)
            local total_len = content_length
            local size, file_found = 0, false
            local chunk_size_limit = 4096
            
            while size < total_len do
                local chunk_size = min(chunk_size_limit, total_len - size)
                local data, _, partial = sock:receive(chunk_size)
                data = data or partial
                if not data then break end
                req.append_body(data)
                size = size + #data
                -- 正文注入检测
                if check_body(data) then return "block", "Multipart Body" end
                -- 文件后缀检测状态机
                if not file_found then
                    local ext = match(data, [[filename=".-%.([^%.%s"]+)"]]) or
                                match(data, [[filename='.-%.([^%.%s']+)']]) or
                                match(data, [[filename=.-%.([^%.%s;]+)]])
                    if ext then
                        if check_file_ext(ext) then return "block", "File Ext" end
                        file_found = true
                    end
                end
            end
            req.finish_body()
            
        -- 普通表单处理
        else
            req.read_body()
            local body = req.get_body_data()
            
            -- 先检测原始 body
            if body and check_body(body) then return "block", "POST Body" end
            
            local post_args = req.get_post_args()
            if post_args then
                for key, val in pairs(post_args) do
                    -- 检测参数名
                    if type(key) == "string" and check_body(key) then return "block", "POST Key" end
                    -- 检测参数值
                    if type(val) == "table" then
                        for _, v in ipairs(val) do
                            if type(v) == "string" and check_body(v) then return "block", "POST Val" end
                        end
                    elseif type(val) == "string" and check_body(val) then
                        return "block", "POST Val"
                    end
                end
            end
        end
    end

    return "pass", "Clean"
end

-- 使用 pcall 安全执行
local ok, action, reason = pcall(waf_check)

if not ok then
    -- 出错时：记录错误并阻止请求（安全优先）
    local err_msg = action or "unknown error"
    ngx.log(ngx.ERR, "WAF Error: ", err_msg, " URI: ", var.request_uri)
    ngx.header.content_type = "text/html"
    ngx.status = 403
    ngx.say("<!-- WAF Error: blocked for safety -->")
    ngx.say(html or "Blocked by WAF")
    ngx.exit(403)
elseif action == "block" then
    -- 已在检测函数中处理拦截，这里只需返回
    return
end
-- action == "pass" 时正常放行
