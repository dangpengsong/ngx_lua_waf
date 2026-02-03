<?php
/**
 * WAF 诊断测试脚本
 * 用于定位随机绕过问题
 */

$target = "http://www.debian12.com";

// 测试用例（每个用例分别测试 GET 和 POST）
$testCases = [
    // SQL 注入
    ["name" => "SQL-Union基础", "payload" => "id=1' UNION SELECT 1,2,3--"],
    ["name" => "SQL-注释混淆", "payload" => "id=1'/**/UNION/**/SELECT/**/1,user(),3--"],
    ["name" => "SQL-双重编码", "payload" => "id=1%2527%2520UNION%2520SELECT%25201%252C2%252C3--"],
    ["name" => "SQL-十六进制", "payload" => "id=0x53454c454354"],
    
    // XSS
    ["name" => "XSS-Script标签", "payload" => "q=<script>alert(1)</script>"],
    ["name" => "XSS-SVG事件", "payload" => "q=<svg/onload=alert(1)>"],
    ["name" => "XSS-IMG事件", "payload" => "q=<img src=x onerror=alert(1)>"],
    
    // 目录遍历
    ["name" => "路径遍历-基础", "payload" => "file=../../../etc/passwd"],
    ["name" => "路径遍历-编码", "payload" => "file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"],
    ["name" => "路径遍历-双重编码", "payload" => "file=%252e%252e%252f%252e%252e%252fetc%252fpasswd"],
    
    // 命令注入
    ["name" => "命令注入-分号", "payload" => "cmd=test;cat /etc/passwd"],
    ["name" => "命令注入-管道", "payload" => "cmd=test|id"],
    ["name" => "命令注入-env", "payload" => "cmd=env && cat /etc/issue"],
    
    // Log4j
    ["name" => "Log4j-JNDI基础", "payload" => "user=\${jndi:ldap://127.0.0.1/a}"],
    ["name" => "Log4j-变形", "payload" => "user=\${jndi:\${lower:l}dap://127.0.0.1/a}"],
    
    // SSRF
    ["name" => "SSRF-本地", "payload" => "url=http://127.0.0.1"],
    ["name" => "SSRF-内网", "payload" => "url=http://192.168.1.1"],
    
    // 反序列化
    ["name" => "PHP反序列化", "payload" => "data=O:4:\"User\":1:{s:4:\"name\";s:5:\"admin\";}"],
];

echo "=== WAF 诊断测试 ===\n";
echo "目标: $target\n";
echo "时间: " . date('Y-m-d H:i:s') . "\n";
echo str_repeat("=", 70) . "\n\n";

$results = [];

foreach ($testCases as $test) {
    $name = $test['name'];
    $payload = $test['payload'];
    
    echo "【{$name}】\n";
    echo "  Payload: " . substr($payload, 0, 60) . (strlen($payload) > 60 ? "..." : "") . "\n";
    
    // 测试 GET 请求（运行3次检查一致性）
    // 正确编码 URL 参数
    if (strpos($payload, '=') !== false) {
        list($key, $val) = explode('=', $payload, 2);
        $encoded_payload = urlencode($key) . '=' . urlencode($val);
    } else {
        $encoded_payload = urlencode($payload);
    }
    
    $getCodes = [];
    for ($i = 0; $i < 3; $i++) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $target . "?" . $encoded_payload);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_USERAGENT, "WAF-Test/1.0");
        curl_exec($ch);
        $getCodes[] = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        usleep(100000); // 100ms 间隔
    }
    
    // 测试 POST 请求（运行3次检查一致性）
    $postCodes = [];
    for ($i = 0; $i < 3; $i++) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $target);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_USERAGENT, "WAF-Test/1.0");
        curl_exec($ch);
        $postCodes[] = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        usleep(100000);
    }
    
    // 分析 GET 结果
    $getUnique = array_unique($getCodes);
    $getStatus = (count($getUnique) == 1 && $getCodes[0] >= 400) ? "✅拦截" : 
                 (count($getUnique) == 1 && $getCodes[0] < 400 ? "❌绕过" : "⚠️不稳定");
    
    // 分析 POST 结果
    $postUnique = array_unique($postCodes);
    $postStatus = (count($postUnique) == 1 && $postCodes[0] >= 400) ? "✅拦截" : 
                  (count($postUnique) == 1 && $postCodes[0] < 400 ? "❌绕过" : "⚠️不稳定");
    
    echo "  GET:  [{$getCodes[0]}, {$getCodes[1]}, {$getCodes[2]}] => $getStatus\n";
    echo "  POST: [{$postCodes[0]}, {$postCodes[1]}, {$postCodes[2]}] => $postStatus\n";
    
    // 记录问题用例
    if ($getStatus != "✅拦截" || $postStatus != "✅拦截") {
        $results[] = [
            "name" => $name,
            "payload" => $payload,
            "get" => implode(",", $getCodes),
            "post" => implode(",", $postCodes),
            "get_status" => $getStatus,
            "post_status" => $postStatus,
        ];
    }
    echo "\n";
}

// 输出问题汇总
echo str_repeat("=", 70) . "\n";
echo "=== 问题汇总 ===\n";
echo str_repeat("=", 70) . "\n";

if (empty($results)) {
    echo "所有测试用例均稳定拦截！\n";
} else {
    echo "发现 " . count($results) . " 个问题用例：\n\n";
    foreach ($results as $r) {
        echo "【{$r['name']}】\n";
        echo "  Payload: {$r['payload']}\n";
        echo "  GET:  {$r['get']} => {$r['get_status']}\n";
        echo "  POST: {$r['post']} => {$r['post_status']}\n\n";
    }
}

// 测试 Header 注入（Log4j 场景）
echo str_repeat("=", 70) . "\n";
echo "=== Header 注入测试 ===\n";
echo str_repeat("=", 70) . "\n";

$headerTests = [
    ["name" => "UA-Log4j", "header" => "User-Agent: \${jndi:ldap://127.0.0.1/a}"],
    ["name" => "Referer-XSS", "header" => "Referer: <script>alert(1)</script>"],
    ["name" => "X-Forwarded-Log4j", "header" => "X-Forwarded-For: \${jndi:ldap://x/}"],
];

foreach ($headerTests as $ht) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $target . "/test");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [$ht['header']]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    $status = ($code >= 400) ? "✅拦截($code)" : "❌绕过($code)";
    echo "【{$ht['name']}】 $status\n";
    echo "  Header: {$ht['header']}\n\n";
}

echo "=== 测试完成 ===\n";
