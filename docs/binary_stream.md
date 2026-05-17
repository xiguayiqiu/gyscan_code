# binary_stream - 二进制流操作库

通过二进制流将数据生成对应文件，以及对文件进行二进制编辑，支持大端/小端字节序、多类型数据读写和链式流操作。实现 `io.Reader` / `io.Writer` / `io.Seeker` / `io.Closer` 标准库接口，无缝对接 `io.Copy`、`encoding/binary` 等所有标准库函数。

## 引入

```go
import "github.com/xiguayiqiu/gyscan_code/binary_stream"
```

---

## 极简 API

```go
// 从字节切片创建 Stream
s := binary_stream.NewFromBytes([]byte{0x01, 0x02, 0x03})

// 从文件读取
s, _ := binary_stream.ReadFile("data.bin")

// 从 io.Reader 读取
s, _ := binary_stream.NewFromReader(strings.NewReader("data"))

// 保存到文件
s.SaveToFile("output.bin")

// 大端/小端快捷创建
s := binary_stream.NewBE()                  // 大端字节序
s := binary_stream.NewLE()                  // 小端字节序
s := binary_stream.NewWithOrder(binary.LittleEndian) // 显式指定字节序

// 预分配容量（避免频繁扩容）
s := binary_stream.NewWithCap(4096)

// 链式构建并保存到文件
binary_stream.BuildToFile("data.bin", func(s *binary_stream.Stream) {
    s.WriteString("HEADER")
    s.WriteUint32(100)
    s.WriteBytes([]byte{0xFF, 0xFE})
})

// 编辑文件
binary_stream.EditFile("data.bin", func(s *binary_stream.Stream) {
    s.Patch(0, []byte{0xAA, 0xBB})
})
```

---

## 标准库接口

`Stream` 实现了 Go 标准库四大 IO 接口，可直接与生态工具配合使用：

| 接口 | 方法 | 说明 |
|------|------|------|
| `io.Reader` | `Read(p []byte) (n int, err error)` | 读取数据到 p |
| `io.Writer` | `Write(p []byte) (n int, err error)` | 从当前位置覆盖写入 |
| `io.Seeker` | `Seek(offset int64, whence int) (int64, error)` | 移动读写位置 |
| `io.Closer` | `Close() error` | 释放底层缓冲 |

```go
s := binary_stream.NewFromBytes([]byte("Hello World"))

// 配合 io.Copy
var buf bytes.Buffer
io.Copy(&buf, s)

// 配合 io.ReadAll
data, _ := io.ReadAll(s)

// 配合 encoding/binary
var header struct { Magic uint32; Size uint16 }
binary.Read(s, binary.BigEndian, &header)
```

> **Write 语义**：`Write` 从当前位置**覆盖写入**（扩展缓冲区但不推挤后续数据）。如需推挤数据，请使用 `Insert`。

---

## 类型定义

### Stream - 二进制流对象

| 字段 | 类型 | 说明 |
|------|------|------|
| 内部缓冲区 | `[]byte` | 存储二进制数据 |
| 读写位置 | `int` | 当前读/写指针位置 |
| 字节序 | `binary.ByteOrder` | 大端(BigEndian)或小端(LittleEndian)，默认大端 |
| 错误状态 | `error` | 最近一次操作的错误 |

---

## 构造函数

| 函数 | 说明 | 返回值 |
|------|------|--------|
| `binary_stream.New()` | 创建空 Stream（默认大端） | `*Stream` |
| `binary_stream.NewWithOrder(order)` | 创建指定字节序的空 Stream | `*Stream` |
| `binary_stream.NewWithCap(capacity)` | 创建指定初始容量的空 Stream | `*Stream` |
| `binary_stream.NewFromBytes(data)` | 从字节切片创建 Stream | `*Stream` |
| `binary_stream.NewFromFile(path)` | 从文件创建 Stream | `(*Stream, error)` |
| `binary_stream.NewFromReader(r)` | 从 io.Reader 创建 Stream | `(*Stream, error)` |
| `binary_stream.NewBE()` | 创建大端字节序 Stream | `*Stream` |
| `binary_stream.NewLE()` | 创建小端字节序 Stream | `*Stream` |

```go
// 创建空流
s := binary_stream.New()

// 显式指定字节序
s := binary_stream.NewWithOrder(binary.LittleEndian)

// 预分配容量，避免频繁扩容
s := binary_stream.NewWithCap(8192)

// 从已有数据创建
s := binary_stream.NewFromBytes([]byte{0xAA, 0xBB, 0xCC})

// 从文件加载
s, err := binary_stream.NewFromFile("payload.bin")

// 从任意 io.Reader 创建
s, err := binary_stream.NewFromReader(response.Body)
defer response.Body.Close()

// 大端流
be := binary_stream.NewBE()
be.WriteUint32(0x01020304)
fmt.Printf("%X\n", be.Bytes())
// 输出: 01020304

// 小端流
le := binary_stream.NewLE()
le.WriteUint32(0x01020304)
fmt.Printf("%X\n", le.Bytes())
// 输出: 04030201
```

---

## 基础操作

### 数据获取

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `.Bytes()` | 返回内部字节切片 | `[]byte` |
| `.Len()` | 数据长度 | `int` |
| `.Cap()` | 内部容量 | `int` |
| `.Slice(start, end)` | 截取指定范围（安全拷贝） | `[]byte` |

```go
s := binary_stream.NewFromBytes([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})

fmt.Println(s.Len())       // 10
fmt.Println(s.Cap())       // >= 10
slice := s.Slice(2, 6)
fmt.Printf("%v\n", slice)  // [2 3 4 5]
```

### 内存管理

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `.Grow(n)` | 确保内部缓冲区至少有 n 字节可用空间 | `*Stream` |
| `.Reset()` | 重置为空，复用底层对象减少 GC | `*Stream` |
| `.Close()` | 实现 io.Closer，释放底层缓冲 | `error` |

```go
s := binary_stream.New()

// 预分配 4KB，避免后续写入时频繁扩容
s.Grow(4096)
s.WriteBytes(largeData)  // 不会触发扩容

// 复用对象
s.Reset()
s.WriteString("New data")  // 复用已分配的内存

// 释放
s.Close()
```

### 位置操作

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `.Pos()` | 获取当前读写位置 | `int` |
| `.SetPos(pos)` | 设置读写位置（返回自身链式调用） | `*Stream` |
| `.Seek(offset, whence)` | io.Seeker 接口（0=头,1=当前,2=尾） | `(int64, error)` |
| `.SeekTo(offset, whence)` | 链式移动读写位置 | `*Stream` |
| `.Remaining()` | 剩余可读字节数 | `int` |
| `.EOF()` | 判断是否已到末尾 | `bool` |

```go
s := binary_stream.NewFromBytes([]byte("Hello World!"))

fmt.Println(s.Pos())       // 0
fmt.Println(s.Remaining()) // 12
fmt.Println(s.EOF())       // false

s.SetPos(6)
fmt.Println(s.Pos())       // 6
fmt.Println(string(s.ReadAll())) // "World!"

// Seek 用法（io.Seeker 接口）
s.Seek(0, io.SeekStart)   // 回到开头
s.Seek(5, io.SeekCurrent) // 从当前位置前移5字节
s.Seek(-3, io.SeekEnd)    // 移动到末尾前3字节

// SeekTo 链式用法
s.SeekTo(0, 0)   // 回到开头
s.SeekTo(5, 1)   // 从当前位置前移5字节
s.SeekTo(-3, 2)  // 移动到末尾前3字节
```

### 状态管理

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `.Error()` | 获取最近错误 | `error` |
| `.ClearError()` | 清除错误状态（返回自身） | `*Stream` |
| `.Must()` | 检查错误状态，有错误则 panic | `*Stream` |
| `.Clone()` | 深拷贝 Stream | `*Stream` |
| `.Order()` | 获取当前字节序 | `binary.ByteOrder` |
| `.SetOrder(order)` | 设置字节序（返回自身） | `*Stream` |
| `.HexDump()` | 十六进制转储字符串 | `string` |

```go
s := binary_stream.NewFromBytes([]byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD})

// 克隆
clone := s.Clone()
clone.WriteByte(0xAA)
// s 不受影响

// HexDump
fmt.Println(s.HexDump())
// 00 01 02 FF FE FD

// 错误处理链式模式
s.ReadUint32()
s.WriteString("fail")
if s.Error() != nil {
    s.ClearError()  // 清除错误后继续
}

// Must 严格模式
s.ReadUint32().Must()  // 如果有错误则 panic
```

---

## 读取操作

所有读取操作从当前 `pos` 位置读取，读取完毕后自动前进位置。读到末尾时设置 `EOF` 错误。

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `.ReadByte()` | 读取1字节 | `byte` |
| `.ReadBytes(n)` | 读取n字节（安全拷贝） | `[]byte` |
| `.UnsafeReadBytes(n)` | 读取n字节（零拷贝，返回内部引用） | `[]byte` |
| `.ReadString(n)` | 读取n字节并转字符串 | `string` |
| `.ReadUint8()` | 读取 uint8 | `uint8` |
| `.ReadUint16()` | 读取 uint16（当前字节序） | `uint16` |
| `.ReadUint32()` | 读取 uint32（当前字节序） | `uint32` |
| `.ReadUint64()` | 读取 uint64（当前字节序） | `uint64` |
| `.ReadInt8()` | 读取 int8 | `int8` |
| `.ReadInt16()` | 读取 int16（当前字节序） | `int16` |
| `.ReadInt32()` | 读取 int32（当前字节序） | `int32` |
| `.ReadInt64()` | 读取 int64（当前字节序） | `int64` |
| `.ReadFloat32()` | 读取 float32（IEEE 754，当前字节序） | `float32` |
| `.ReadFloat64()` | 读取 float64（IEEE 754，当前字节序） | `float64` |
| `.ReadVarint()` | 读取变长有符号整数（ZigZag编码） | `int64` |
| `.ReadUvarint()` | 读取变长无符号整数 | `uint64` |
| `.ReadBool()` | 读取布尔值（1字节） | `bool` |
| `.ReadAll()` | 读取所有剩余字节 | `[]byte` |
| `.ReadUntil(delim)` | 读取直到遇到指定字节（不含） | `[]byte` |

```go
s := binary_stream.NewFromBytes([]byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC})

// 逐字节读取
b1 := s.ReadByte()    // 0x00
b2 := s.ReadUint8()   // 0x01

// 多字节读取（大端序）
v16 := s.ReadUint16()  // 0x0203
v32 := s.ReadUint32()  // 0xFFFEFDFC

// Varint（ZigZag编码）
s2 := binary_stream.NewFromBytes([]byte{0x01})  // 1 的 Varint 编码
v := s2.ReadVarint()  // 1

// 布尔读取
flag := s2.ReadBool() // true/false

// 零拷贝读取（只读场景，不要修改返回数据！）
ref := s.UnsafeReadBytes(4)  // 直接引用内部缓冲区，无拷贝

// ReadUntil
s.SetPos(0)
data := s.ReadUntil(0xFF)
fmt.Printf("%X\n", data)  // 00010203  (读到0xFF之前)
```

> **UnsafeReadBytes 警告**：返回的是内部缓冲区的切片引用，不要修改返回的数据，否则会破坏内部状态。仅适用于只读解析场景。

### 解析 Protobuf Varint 示例

```go
// 解析 Protobuf 格式的整数
s, _ := binary_stream.NewFromFile("proto.bin")
fieldNum := s.ReadVarint()
value := s.ReadVarint()
fmt.Printf("Field %d: %d\n", fieldNum, value)
```

### 解析二进制文件头示例

```go
// 解析 PE 文件头
s, _ := binary_stream.NewFromFile("example.exe")
s.SetOrder(binary.LittleEndian)

// DOS Header
magic := s.ReadString(2)          // "MZ"
s.SeekTo(60, 0)                    // e_lfanew
peOffset := s.ReadUint32()

// PE Header
s.SetPos(int(peOffset))
peSig := s.ReadString(4)          // "PE\x00\x00"
machine := s.ReadUint16()         // 机器类型
numSections := s.ReadUint16()     // 节数量
```

---

## 写入操作

所有写入操作从当前 `pos` 位置**覆盖写入**。如果位置超出缓冲区末尾，自动扩容。如需推挤后续数据，请使用 `Insert`。

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `.WriteByte(b)` | 写入1字节 | `*Stream` |
| `.WriteBytes(data)` | 写入字节切片 | `*Stream` |
| `.WriteString(str)` | 写入字符串 | `*Stream` |
| `.WriteUint8(v)` | 写入 uint8 | `*Stream` |
| `.WriteUint16(v)` | 写入 uint16（当前字节序） | `*Stream` |
| `.WriteUint32(v)` | 写入 uint32（当前字节序） | `*Stream` |
| `.WriteUint64(v)` | 写入 uint64（当前字节序） | `*Stream` |
| `.WriteInt8(v)` | 写入 int8 | `*Stream` |
| `.WriteInt16(v)` | 写入 int16（当前字节序） | `*Stream` |
| `.WriteInt32(v)` | 写入 int32（当前字节序） | `*Stream` |
| `.WriteInt64(v)` | 写入 int64（当前字节序） | `*Stream` |
| `.WriteFloat32(v)` | 写入 float32（IEEE 754，当前字节序） | `*Stream` |
| `.WriteFloat64(v)` | 写入 float64（IEEE 754，当前字节序） | `*Stream` |
| `.WriteVarint(v)` | 写入变长有符号整数（ZigZag编码） | `*Stream` |
| `.WriteUvarint(v)` | 写入变长无符号整数 | `*Stream` |
| `.WriteBool(v)` | 写入布尔值（1字节，true=1, false=0） | `*Stream` |
| `.WriteZero(n)` | 写入n个零字节 | `*Stream` |
| `.WriteRepeat(b, n)` | 重复写入某字节n次 | `*Stream` |

```go
s := binary_stream.New()

// 链式写入
s.WriteByte(0xFF).
  WriteUint16(0x1234).
  WriteUint32(0x56789ABC).
  WriteString("DATA")

fmt.Printf("%X\n", s.Bytes())
// 输出: FF123456789ABC44415441

// 数值写入
s2 := binary_stream.New()
s2.WriteUint8(255)        // 0xFF
s2.WriteInt16(-32768)     // 0x8000（大端）
s2.WriteFloat32(3.14)     // IEEE 754 编码

// Varint 写入（Protobuf 风格）
s2.WriteVarint(150)        // 2字节：9601
s2.WriteVarint(-150)       // ZigZag：2B02

// 布尔写入
s2.WriteBool(true)         // 01
s2.WriteBool(false)        // 00

// 填充写入
s3 := binary_stream.New()
s3.WriteZero(4)           // 4个0x00
s3.WriteRepeat(0xAA, 5)   // 5个0xAA
```

### 构建 Protobuf 消息示例

```go
s := binary_stream.New()
s.WriteVarint(1)           // field number
s.WriteString("hello")     // string value
s.WriteVarint(2)           // field number
s.WriteVarint(42)          // int value
s.WriteVarint(3)           // field number
s.WriteBool(true)          // bool value
```

---

## 文件操作

### Stream 方法

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `.SaveToFile(path)` | 保存当前数据到文件 | `error` |
| `.LoadFromFile(path)` | 从文件加载数据（重置） | `error` |
| `.AppendToFile(path)` | 追加当前数据到文件 | `error` |

```go
// 构建并保存
s := binary_stream.New()
s.WriteString("Payload")
s.WriteZero(4)
err := s.SaveToFile("payload.bin")

// 加载文件
s2 := binary_stream.New()
err = s2.LoadFromFile("payload.bin")
s2.SetPos(0)
header := s2.ReadString(7)
fmt.Println(header)  // "Payload"

// 追加数据
extra := binary_stream.NewFromBytes([]byte("APPEND"))
extra.AppendToFile("payload.bin")
```

### 包级文件快捷函数

| 函数 | 说明 | 返回值 |
|------|------|--------|
| `binary_stream.ReadFile(path)` | 读取文件为 Stream | `(*Stream, error)` |
| `binary_stream.ReadFileBytes(path)` | 读取文件为字节切片 | `([]byte, error)` |
| `binary_stream.CreateFile(path, data)` | 用字节切片创建文件 | `error` |
| `binary_stream.CreateFileFromStream(path, s)` | 用 Stream 创建文件 | `error` |
| `binary_stream.GenerateFile(path, fn)` | 链式构建并生成文件 | `error` |
| `binary_stream.FileExists(path)` | 判断文件是否存在 | `bool` |
| `binary_stream.FileSize(path)` | 获取文件大小 | `(int64, error)` |

```go
// 直接读取
s, err := binary_stream.ReadFile("data.bin")
data, err := binary_stream.ReadFileBytes("data.bin")

// 直接写入
binary_stream.CreateFile("output.bin", []byte{0xAA, 0xBB})

// 链式构建
binary_stream.GenerateFile("config.bin", func(s *binary_stream.Stream) {
    s.WriteString("HEADER")
    s.WriteUint32(100)
    s.WriteString("DATA")
})

// 文件检查
if binary_stream.FileExists("data.bin") {
    size, _ := binary_stream.FileSize("data.bin")
    fmt.Printf("size: %d bytes\n", size)
}
```

---

## 编辑操作

在 Stream 内部修改二进制数据。

### 覆盖与替换

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `.Patch(offset, data)` | 在指定偏移处覆盖写入（定长，严格边界检查） | `*Stream` |
| `.Replace(start, end, data)` | 替换指定范围的数据（可不同长度） | `*Stream` |

```go
s := binary_stream.NewFromBytes([]byte("Hello World!"))

// Patch：定长覆盖
s.Patch(6, []byte("XXX"))   // "Hello XXXld!"
fmt.Println(string(s.Bytes()))

// Replace：可变长度替换
s2 := binary_stream.NewFromBytes([]byte("Hello World!"))
s2.Replace(6, 11, []byte("Go"))  // "Hello Go!"
fmt.Println(string(s2.Bytes()))
```

### 插入与删除

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `.Insert(offset, data)` | 在指定位置插入数据（推挤后续数据） | `*Stream` |
| `.Delete(start, end)` | 删除指定范围的数据 | `*Stream` |

```go
s := binary_stream.NewFromBytes([]byte("Hello World!"))

// Insert：插入数据
s.Insert(5, []byte(" Go!"))
fmt.Println(string(s.Bytes()))  // "Hello Go! World!"

// Delete：删除范围
s2 := binary_stream.NewFromBytes([]byte("HelloXXXWorld"))
s2.Delete(5, 8)
fmt.Println(string(s2.Bytes()))  // "HelloWorld"
```

### 截断

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `.Truncate(length)` | 截断 Stream 到指定长度 | `*Stream` |

```go
s := binary_stream.NewFromBytes([]byte("Hello World!"))
s.Truncate(5)
fmt.Println(string(s.Bytes()))  // "Hello"
```

### 文件编辑便捷函数

| 函数 | 说明 | 返回值 |
|------|------|--------|
| `binary_stream.EditFile(path, fn)` | 读取文件、传入编辑函数、保存 | `error` |
| `binary_stream.PatchFile(path, offset, data)` | 文件指定偏移覆盖写入 | `error` |
| `binary_stream.ReplaceInFile(path, start, end, data)` | 文件指定范围替换 | `error` |
| `binary_stream.InsertIntoFile(path, offset, data)` | 文件指定位置插入 | `error` |
| `binary_stream.DeleteFromFile(path, start, end)` | 文件指定范围删除 | `error` |
| `binary_stream.TruncateFile(path, length)` | 文件截断到指定长度 | `error` |

```go
// 灵活编辑
binary_stream.EditFile("data.bin", func(s *binary_stream.Stream) {
    s.Replace(4, 8, []byte{0xAA, 0xBB, 0xCC})
    s.Insert(0, []byte("NEW_HEADER"))
})

// 快捷函数
binary_stream.PatchFile("data.bin", 4, []byte{0xFF})           // 偏移4处覆盖
binary_stream.ReplaceInFile("data.bin", 0, 4, []byte("HELO"))   // 范围替换
binary_stream.InsertIntoFile("data.bin", 0, []byte("PREFIX"))   // 开头插入
binary_stream.DeleteFromFile("data.bin", 10, 20)                 // 范围删除
binary_stream.TruncateFile("data.bin", 100)                      // 截断
```

---

## 便捷构建函数

| 函数 | 说明 | 返回值 |
|------|------|--------|
| `binary_stream.Build(fn)` | 链式构建返回 Stream | `*Stream` |
| `binary_stream.BuildBytes(fn)` | 链式构建返回字节切片 | `[]byte` |
| `binary_stream.BuildToFile(path, fn)` | 链式构建并保存到文件 | `error` |

```go
// 构建 Stream
s := binary_stream.Build(func(s *binary_stream.Stream) {
    s.WriteString("PACKET")
    s.WriteUint32(42)
    s.WriteZero(8)
})

// 直接获取字节
b := binary_stream.BuildBytes(func(s *binary_stream.Stream) {
    s.WriteUint16(0xABCD)  // 大端: AB CD
    s.WriteBytes([]byte{0xFF, 0xFE})
})
fmt.Printf("%X\n", b)  // ABCDFFFE

// 构建并写入文件
binary_stream.BuildToFile("packet.bin", func(s *binary_stream.Stream) {
    s.WriteString("MAGIC")
    s.WriteUint32(headerLen)
    s.WriteBytes(payload)
})
```

---

## 比较与合并

| 函数 | 说明 | 返回值 |
|------|------|--------|
| `binary_stream.Compare(a, b)` | 比较两个字节切片 | `bool` |
| `binary_stream.CompareFiles(p1, p2)` | 比较两个文件 | `(bool, error)` |
| `binary_stream.MergeBytes(chunks...)` | 合并多个字节切片 | `[]byte` |
| `binary_stream.MergeStreams(streams...)` | 合并多个 Stream | `*Stream` |

```go
// 数据比较
if binary_stream.Compare(data1, data2) {
    fmt.Println("数据相同")
}

// 文件比较
same, _ := binary_stream.CompareFiles("file1.bin", "file2.bin")

// 合并
merged := binary_stream.MergeBytes(
    []byte("Part1"),
    []byte("Part2"),
    []byte("Part3"),
)
fmt.Println(string(merged))  // "Part1Part2Part3"
```

---

## 典型使用场景

### 场景1：解析自定义二进制协议

```go
s, _ := binary_stream.NewFromFile("protocol.bin")
s.SetOrder(binary.LittleEndian)

// 读取协议头
magic := s.ReadUint16()
version := s.ReadByte()
length := s.ReadUint32()
payload := s.ReadBytes(int(length))

fmt.Printf("Magic: 0x%04X, Version: %d, Length: %d\n", magic, version, length)
```

### 场景2：生成二进制配置文件

```go
binary_stream.BuildToFile("config.bin", func(s *binary_stream.Stream) {
    s.SetOrder(binary.LittleEndian)

    // 文件头
    s.WriteUint32(0x4D414749) // "MAGI"
    s.WriteUint16(1)           // version
    s.WriteZero(2)             // reserved

    // 配置项
    s.WriteUint32(1920)        // width
    s.WriteUint32(1080)        // height
    s.WriteFloat64(60.0)       // fps
})
```

### 场景3：修改PE/ELF文件字节

```go
binary_stream.EditFile("target.exe", func(s *binary_stream.Stream) {
    // 修改文件头中某个偏移的值
    s.Patch(0x120, []byte{0x90, 0x90, 0x90, 0x90, 0x90}) // NOP指令

    // 增大一个节
    s.Insert(0x400, make([]byte, 0x200))
})
```

### 场景4：高性能网络包解析（零拷贝）

```go
s := binary_stream.NewFromBytes(networkPacket)
magic := s.UnsafeReadBytes(4)      // 零拷贝，直接引用
length := s.ReadUint32()
payload := s.UnsafeReadBytes(int(length)) // 零拷贝
// 注意：不要修改 magic 和 payload，它们是内部缓冲区的引用
```

### 场景5：合并多个二进制片段

```go
header := binary_stream.New()
header.WriteString("HEADER")
header.WriteZero(4)

body := binary_stream.New()
body.WriteString("BODY_DATA")

footer := binary_stream.New()
footer.WriteString("FOOTER")

// 合并为一个文件
binary_stream.MergeStreams(header, body, footer).SaveToFile("complete.bin")
```

### 场景6：对象池复用（减少 GC 压力）

```go
// 使用 sync.Pool 复用 Stream 对象
var streamPool = sync.Pool{
    New: func() interface{} {
        return binary_stream.NewWithCap(4096)
    },
}

func processPacket(data []byte) {
    s := streamPool.Get().(*binary_stream.Stream)
    s.Reset()
    s.WriteBytes(data)
    // ... 处理 ...
    streamPool.Put(s)
}
```

---

## Shellcode - 交互式二进制 Shell

`Shellcode` 函数启动一个交互式二进制编辑 shell，提示符 `hex>>`，支持对文件进行增删改查操作。

### 启动方式

```go
// 基础 Shell
binary_stream.Shellcode("/path/to/file.bin")

// 带命令历史记录
binary_stream.ShellcodeWithHistory("/path/to/file.bin")

// 脚本执行模式
err := binary_stream.ShellcodeScript("/path/to/file.bin", "commands.txt")
```

### 命令一览

| 分类 | 命令 | 说明 | 示例 |
|------|------|------|------|
| 文件 | `open <path>` | 打开文件 | `open data.bin` |
| 文件 | `save` | 保存到当前文件 | `save` |
| 文件 | `saveas <path>` | 另存为 | `saveas output.bin` |
| 文件 | `info` | 显示文件信息 | `info` |
| 文件 | `len` | 显示数据长度 | `len` |
| 文件 | `exit` / `quit` | 退出（修改后提示保存） | `exit` |
| 数据 | `hexdump [n]` | 十六进制转储 | `hexdump 10` |
| 数据 | `read <off> <n>` | 读取 n 字节（十六进制） | `read 0x100 16` |
| 数据 | `str <off> <n>` | 读取 n 字节（字符串） | `str 0 8` |
| 数据 | `find <hex>` | 搜索字节 | `find 89504E47` |
| 编辑 | `write <off> <hex>` | 覆盖写入（定长，不越界） | `write 4 48454C4C4F` |
| 编辑 | `insert <off> <hex>` | 插入数据 | `insert 0 505245` |
| 编辑 | `delete <off> <n>` | 删除 n 字节 | `delete 0 5` |
| 编辑 | `replace <s> <e> <hex>` | 替换范围数据 | `replace 5 8 585858` |
| 编辑 | `truncate <len>` | 截断到指定长度 | `truncate 100` |
| 定位 | `pos <off>` | 设置读写位置 | `pos 0x200` |
| 定位 | `seek <off> <w>` | whence=0/1/2 移动 | `seek -4 2` |
| 定位 | `rem` | 剩余可读字节 | `rem` |
| 定位 | `eof` | 是否到末尾 | `eof` |
| 其他 | `undo` | 重新加载（撤销修改） | `undo` |
| 其他 | `help` | 显示帮助 | `help` |
| 其他 | `q` | 快速退出（不保存） | `q` |

### ShellcodeWithHistory

`ShellcodeWithHistory` 与 `Shellcode` 功能相同，但额外支持命令历史记录：
- 输入过的命令被保存到历史列表中
- 程序退出时自动记录最后 1000 条命令
- 程序内可通过 `history` 结构体字段回顾历史

```go
// 启动带历史记录的 Shell
binary_stream.ShellcodeWithHistory("/path/to/target.bin")
```

### 脚本执行模式

`ShellcodeScript` 支持从脚本文件读取命令并自动执行，适用于自动化测试或批处理：

```bash
# commands.txt
# 这是一条注释
read 0 16
insert 8 DEADBEEF
hexdump 5
saveas output.bin
exit
```

```go
err := binary_stream.ShellcodeScript("data.bin", "commands.txt")
if err != nil {
    log.Fatal(err)
}
```

脚本文件规则：
- 每行一条命令
- `#` 开头的行为注释
- 空行被忽略
- 脚本执行完毕后自动保存（如有修改）

### 使用示例

```bash
$ go run -exec "binary_stream.Shellcode" data.bin
hex>> info
文件: data.bin
大小: 256 bytes (0x100)
位置: 0 (0x0)
脏标记: false

hex>> read 0 8
00000000  89 50 4E 47 0D 0A 1A 0A                           |.PNG....|
  (8 bytes, offset 0x0-0x7)

hex>> find 504E47
  匹配 @ 0x1 (1)
共找到 1 个匹配

hex>> insert 8 DEADBEEF
已插入 4 bytes @ 0x8，新大小: 260 bytes

hex>> write 4 48454C4C4F
写入超出范围 (offset=4, size=5, total=260)
# write 是覆盖写入，不能越界，请用 insert 扩展文件

hex>> delete 0 8
已删除 8 bytes @ 0x0，新大小: 252 bytes

hex>> undo
已撤销更改，重新加载: data.bin (256 bytes)

hex>> exit
再见!
```

### 代码集成示例

```go
package main

import "github.com/xiguayiqiu/gyscan_code/binary_stream"

func main() {
    // 方式1：基础交互式 shell
    binary_stream.Shellcode("/path/to/target.bin")

    // 方式2：带历史记录的 shell
    binary_stream.ShellcodeWithHistory("/path/to/target.bin")

    // 方式3：脚本批量处理
    if err := binary_stream.ShellcodeScript("/path/to/target.bin", "script.txt"); err != nil {
        log.Fatalf("脚本执行失败: %v", err)
    }
}
```

---

## 性能建议

1. **预分配容量**：已知数据量大小时，使用 `NewWithCap(capacity)` 或 `.Grow(n)` 预分配内存，避免频繁扩容。
2. **零拷贝读取**：对于只读解析场景，使用 `UnsafeReadBytes` 减少内存拷贝，但**不要修改返回的数据**。
3. **对象复用**：在高频调用场景中，通过 `Reset()` 复用 Stream 对象，减少 GC 压力。可与 `sync.Pool` 配合使用。
4. **Write 是覆盖语义**：写入从当前位置覆盖数据，不会推挤后续字节。如需推挤，使用 `Insert`。

---

## License

Apache License 2.0