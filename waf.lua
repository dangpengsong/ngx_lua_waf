local var = ngx.var
local req = ngx.req
-- 1. IP 级别防护(最高优先级)
if check_ip_white() then return end
if check_ip_block() then return end
-- 2. 基础识别与 CC 防护
if check_white_url() then return end
if check_cc() then return end
-- 3. 扫描器指纹硬拦截
if var.http_Acunetix_Aspect or var.http_X_Scan_Memo then
    return do_action('SCANNER', var.request_uri, "-", "Scanner Fingerprint")
end
-- 4. 静态特征检测 (UA/URL/Args/Cookie)
if check_ua() or check_url() or check_args() or check_cookie() then
    return
end
-- 5. POST 深度检测 (逻辑规范化)
if post_match == "on" and req.get_method() == "POST" then
    local content_type = var.content_type or ""
    -- Multipart 分块处理
    if string.find(content_type, "multipart/form-data", 1, true) then
        local sock, err = req.socket()
        if not sock then return end
        req.init_body(128 * 1024)
        local total_len = tonumber(var.content_length) or 0
        local size, file_found = 0, false
        while size < total_len do
            local chunk_size = math.min(4096, total_len - size)
            local data, _, partial = sock:receive(chunk_size)
            data = data or partial
            if not data then break end
            req.append_body(data)
            size = size + #data
            -- 正文注入检测
            if check_body(data) then return end
            -- 文件后缀检测状态机
            if not file_found then
                local ext = string.match(data, [[filename=".-%.([^%.%s]+)"]])
                if ext then
                    check_file_ext(ext)
                    file_found = true
                end
            end
        end
        req.finish_body()
    -- 普通表单处理
    else
        req.read_body()
        local post_args = req.get_post_args()
        if post_args then
            for key, val in pairs(post_args) do
                -- 先检测参数名,再检测参数值
                if check_body(key) then return end
                local data = type(val) == "table" and table.concat(val, ", ") or val
                if data and data ~= true then
                    if check_body(data) then return end
                end
            end
        end
    end
end