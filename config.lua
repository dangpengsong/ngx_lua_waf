-- =============================================================================
-- WAF 核心配置文件
-- 建议:修改路径后请确保 Nginx 运行用户(如 www-data)拥有读写权限
-- =============================================================================
-- 规则存放目录 (确保末尾带有斜杠)
rulepath = "/usr/local/openresty/nginx/conf/waf/wafconf/"
-- 日志存储目录 (必须存在且可写,用于存放 hack 记录)
logdir = "/usr/local/openresty/nginx/logs/hack/"
-- ---------------------------------------------------------
-- 功能开关 ("on" 为开启, "off" 为关闭)
-- ---------------------------------------------------------
attacklog    = "on"    -- 是否记录攻击日志
url_deny     = "on"    -- 是否拦截 URL 恶意请求
redirect     = "on"    -- 拦截后是否重定向/输出错误页
cookie_match = "on"    -- 是否拦截 Cookie 注入攻击
post_match   = "on"    -- 是否拦截 POST 注入攻击
white_module = "on"    -- 是否开启 URL 白名单模块
cc_deny      = "on"    -- 是否开启 CC 攻击防护
-- ---------------------------------------------------------
-- 防护规则配置
-- ---------------------------------------------------------
-- 不允许上传的文件后缀
black_fileext = {"php", "jsp", "asp", "exe", "sh"}
-- IP 白名单 (Hash 匹配,优先级最高,支持多个)
ipWhitelist = {"127.0.0.1", "192.168.1.1"}
-- IP 黑名单 (命中直接返回 403)
ipBlocklist = {"1.0.0.1", "8.8.8.8"}
-- CC 频率限制 (格式: 最大请求数/秒数)
-- 示例 "300/60" 表示 60秒内同一个 IP 访问同一个 URL 超过 300 次则拦截
cc_rate = "90/30"
-- ---------------------------------------------------------
-- 拦截响应页面内容
-- ---------------------------------------------------------
html = [[
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>请求被拦截 - 安全防护</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: "Segoe UI", "Microsoft YaHei", sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 50px;
            max-width: 600px;
            width: 100%;
            text-align: center;
            animation: fadeIn 0.6s ease-out;
        }
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .icon {
            font-size: 80px;
            color: #ff4757;
            margin-bottom: 30px;
            animation: shake 0.5s ease-in-out;
        }
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-10px); }
            75% { transform: translateX(10px); }
        }
        h1 {
            color: #2d3436;
            font-size: 32px;
            margin-bottom: 20px;
            font-weight: 600;
        }
        .message {
            color: #636e72;
            font-size: 18px;
            line-height: 1.6;
            margin-bottom: 30px;
        }
        .btn {
            padding: 12px 30px;
            border: none;
            border-radius: 50px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .btn-secondary {
            background: #f1f2f6;
            color: #2d3436;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        .btn:active {
            transform: translateY(0);
        }
        .footer {
            margin-top: 40px;
            color: #a4b0be;
            font-size: 14px;
        }
        @media (max-width: 480px) {
            .container {
                padding: 30px 20px;
            }
            h1 {
                font-size: 24px;
            }
            .message {
                font-size: 16px;
            }
            .btn {
                padding: 10px 20px;
                font-size: 14px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🚫</div>
        <h1>请求被安全防护系统拦截</h1>
        <div class="message">
            检测到您的请求中包含潜在的安全威胁,系统已自动拦截.
        </div>
        <div class="message">
            如果您认为这是误判,请联系网站管理员.
            请确保您的请求符合安全规范,不要尝试绕过安全防护.
        </div>
        <div class="footer">
            <p>waf</p>
        </div>
    </div>
</body>
</html>
]]