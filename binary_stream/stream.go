package binary_stream

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
)

// 编译期接口检查
var _ io.Reader = (*Stream)(nil)
var _ io.Writer = (*Stream)(nil)
var _ io.Seeker = (*Stream)(nil)
var _ io.Closer = (*Stream)(nil)

// Stream 二进制流对象，封装字节切片并提供读写定位功能。
// 实现 io.Reader / io.Writer / io.Seeker / io.Closer 接口，
// 可直接与 io.Copy、encoding/binary 等标准库配合使用。
type Stream struct {
	buf []byte
	pos int
	bo  binary.ByteOrder
	err error
}

// New 创建一个新的空 Stream
func New() *Stream {
	return &Stream{
		buf: make([]byte, 0),
		pos: 0,
		bo:  binary.BigEndian,
	}
}

// NewWithOrder 创建指定字节序的空 Stream
func NewWithOrder(order binary.ByteOrder) *Stream {
	return &Stream{
		buf: make([]byte, 0),
		pos: 0,
		bo:  order,
	}
}

// NewWithCap 创建指定初始容量的空 Stream，避免频繁扩容
func NewWithCap(capacity int) *Stream {
	return &Stream{
		buf: make([]byte, 0, capacity),
		pos: 0,
		bo:  binary.BigEndian,
	}
}

// NewFromBytes 从字节切片创建 Stream
func NewFromBytes(data []byte) *Stream {
	s := NewWithCap(len(data))
	s.WriteBytes(data)
	s.SetPos(0)
	return s
}

// NewFromFile 从文件读取并创建 Stream
func NewFromFile(path string) (*Stream, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("binary_stream: read file %s: %w", path, err)
	}
	return NewFromBytes(data), nil
}

// NewFromReader 从 io.Reader 读取全部数据创建 Stream
func NewFromReader(r io.Reader) (*Stream, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("binary_stream: read from reader: %w", err)
	}
	return NewFromBytes(data), nil
}

// Bytes 返回内部字节切片
func (s *Stream) Bytes() []byte {
	return s.buf
}

// Len 返回数据长度
func (s *Stream) Len() int {
	return len(s.buf)
}

// Cap 返回内部切片容量
func (s *Stream) Cap() int {
	return cap(s.buf)
}

// Pos 返回当前读写位置
func (s *Stream) Pos() int {
	return s.pos
}

// SetPos 设置读写位置
func (s *Stream) SetPos(pos int) *Stream {
	if pos < 0 {
		s.pos = 0
	} else if pos > len(s.buf) {
		s.pos = len(s.buf)
	} else {
		s.pos = pos
	}
	return s
}

// Grow 确保内部缓冲区至少有 n 字节可用空间，用于预分配避免频繁扩容
func (s *Stream) Grow(n int) *Stream {
	if n > cap(s.buf) {
		newBuf := make([]byte, len(s.buf), n)
		copy(newBuf, s.buf)
		s.buf = newBuf
	}
	return s
}

// --- io.Seeker 实现 ---

// Seek 实现 io.Seeker 接口（offset 为 int64，返回 int64 和 error）
func (s *Stream) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = int64(s.pos) + offset
	case io.SeekEnd:
		abs = int64(len(s.buf)) + offset
	default:
		return int64(s.pos), fmt.Errorf("binary_stream: invalid whence %d", whence)
	}
	if abs < 0 {
		abs = 0
	}
	if abs > int64(len(s.buf)) {
		abs = int64(len(s.buf))
	}
	s.pos = int(abs)
	return abs, nil
}

// SeekTo 链式移动读写位置（保持链式调用 API 兼容）
func (s *Stream) SeekTo(offset int, whence int) *Stream {
	switch whence {
	case 0:
		s.SetPos(offset)
	case 1:
		s.SetPos(s.pos + offset)
	case 2:
		s.SetPos(len(s.buf) + offset)
	}
	return s
}

// Remaining 返回剩余可读字节数
func (s *Stream) Remaining() int {
	return len(s.buf) - s.pos
}

// EOF 判断是否已到达末尾
func (s *Stream) EOF() bool {
	return s.pos >= len(s.buf)
}

// Error 返回最近一次操作的错误
func (s *Stream) Error() error {
	return s.err
}

// ClearError 清除错误状态
func (s *Stream) ClearError() *Stream {
	s.err = nil
	return s
}

// Must 检查错误状态，有错误则 panic
func (s *Stream) Must() *Stream {
	if s.err != nil {
		panic(s.err)
	}
	return s
}

// SetOrder 设置字节序
func (s *Stream) SetOrder(order binary.ByteOrder) *Stream {
	s.bo = order
	return s
}

// Order 返回当前字节序
func (s *Stream) Order() binary.ByteOrder {
	return s.bo
}

// Clone 深拷贝当前 Stream
func (s *Stream) Clone() *Stream {
	clone := &Stream{
		buf: make([]byte, len(s.buf)),
		pos: s.pos,
		bo:  s.bo,
		err: s.err,
	}
	copy(clone.buf, s.buf)
	return clone
}

// Reset 重置 Stream 为空，复用底层对象减少 GC 压力
func (s *Stream) Reset() *Stream {
	s.buf = s.buf[:0]
	s.pos = 0
	s.err = nil
	return s
}

// --- io.Closer 实现 ---

// Close 实现 io.Closer 接口（重置 Stream 并释放底层缓冲）
func (s *Stream) Close() error {
	s.buf = nil
	s.pos = 0
	s.err = nil
	return nil
}

// Slice 返回从 pos 到 end 的安全字节切片（拷贝，不影响内部状态）
func (s *Stream) Slice(start, end int) []byte {
	if start < 0 {
		start = 0
	}
	if end > len(s.buf) {
		end = len(s.buf)
	}
	if start >= end {
		return nil
	}
	dst := make([]byte, end-start)
	copy(dst, s.buf[start:end])
	return dst
}

// --- 读取操作 ---

// Read 实现 io.Reader 接口，读取到 p 中最多 len(p) 字节
func (s *Stream) Read(p []byte) (n int, err error) {
	if s.err != nil {
		return 0, s.err
	}
	if s.pos >= len(s.buf) {
		return 0, io.EOF
	}
	n = copy(p, s.buf[s.pos:])
	s.pos += n
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// ReadByte 读取一个字节
func (s *Stream) ReadByte() byte {
	if s.err != nil {
		return 0
	}
	if s.pos >= len(s.buf) {
		s.err = io.EOF
		return 0
	}
	b := s.buf[s.pos]
	s.pos++
	return b
}

// ReadBytes 读取 n 个字节（安全拷贝）
func (s *Stream) ReadBytes(n int) []byte {
	if s.err != nil {
		return nil
	}
	if s.pos+n > len(s.buf) {
		s.err = io.EOF
		return nil
	}
	dst := make([]byte, n)
	copy(dst, s.buf[s.pos:s.pos+n])
	s.pos += n
	return dst
}

// UnsafeReadBytes 读取 n 个字节（零拷贝，返回内部缓冲区的切片引用）
// 警告：不要修改返回的数据，否则会破坏内部状态。适用于只读解析场景。
func (s *Stream) UnsafeReadBytes(n int) []byte {
	if s.err != nil {
		return nil
	}
	if s.pos+n > len(s.buf) {
		s.err = io.EOF
		return nil
	}
	start := s.pos
	s.pos += n
	return s.buf[start:s.pos]
}

// ReadString 读取 n 个字节并转为字符串
func (s *Stream) ReadString(n int) string {
	return string(s.ReadBytes(n))
}

// ReadUint8 读取 uint8
func (s *Stream) ReadUint8() uint8 {
	return s.ReadByte()
}

// ReadUint16 读取 uint16（使用当前字节序）
func (s *Stream) ReadUint16() uint16 {
	if s.err != nil {
		return 0
	}
	if s.pos+2 > len(s.buf) {
		s.err = io.EOF
		return 0
	}
	v := s.bo.Uint16(s.buf[s.pos:])
	s.pos += 2
	return v
}

// ReadUint32 读取 uint32（使用当前字节序）
func (s *Stream) ReadUint32() uint32 {
	if s.err != nil {
		return 0
	}
	if s.pos+4 > len(s.buf) {
		s.err = io.EOF
		return 0
	}
	v := s.bo.Uint32(s.buf[s.pos:])
	s.pos += 4
	return v
}

// ReadUint64 读取 uint64（使用当前字节序）
func (s *Stream) ReadUint64() uint64 {
	if s.err != nil {
		return 0
	}
	if s.pos+8 > len(s.buf) {
		s.err = io.EOF
		return 0
	}
	v := s.bo.Uint64(s.buf[s.pos:])
	s.pos += 8
	return v
}

// ReadInt8 读取 int8
func (s *Stream) ReadInt8() int8 {
	return int8(s.ReadByte())
}

// ReadInt16 读取 int16（使用当前字节序）
func (s *Stream) ReadInt16() int16 {
	return int16(s.ReadUint16())
}

// ReadInt32 读取 int32（使用当前字节序）
func (s *Stream) ReadInt32() int32 {
	return int32(s.ReadUint32())
}

// ReadInt64 读取 int64（使用当前字节序）
func (s *Stream) ReadInt64() int64 {
	return int64(s.ReadUint64())
}

// ReadFloat32 读取 float32（IEEE 754，使用当前字节序）
func (s *Stream) ReadFloat32() float32 {
	return math.Float32frombits(s.ReadUint32())
}

// ReadFloat64 读取 float64（IEEE 754，使用当前字节序）
func (s *Stream) ReadFloat64() float64 {
	return math.Float64frombits(s.ReadUint64())
}

// ReadVarint 读取变长有符号整数（Binary Varint / Protobuf ZigZag 编码）
func (s *Stream) ReadVarint() int64 {
	uval := s.ReadUvarint()
	x := int64(uval >> 1)
	if uval&1 != 0 {
		x = ^x
	}
	return x
}

// ReadUvarint 读取变长无符号整数
func (s *Stream) ReadUvarint() uint64 {
	if s.err != nil {
		return 0
	}
	var x uint64
	var sft uint
	for i := 0; i < binary.MaxVarintLen64; i++ {
		if s.pos >= len(s.buf) {
			s.err = io.EOF
			return 0
		}
		b := s.buf[s.pos]
		s.pos++
		x |= uint64(b&0x7F) << sft
		if b < 0x80 {
			return x
		}
		sft += 7
		if sft >= 64 {
			s.err = fmt.Errorf("binary_stream: varint overflow")
			return 0
		}
	}
	s.err = fmt.Errorf("binary_stream: varint overflow")
	return 0
}

// ReadBool 读取布尔值（1 字节，非零为 true）
func (s *Stream) ReadBool() bool {
	return s.ReadByte() != 0
}

// ReadAll 读取所有剩余字节
func (s *Stream) ReadAll() []byte {
	return s.ReadBytes(s.Remaining())
}

// ReadUntil 读取直到遇到指定字节（不包含该字节）
func (s *Stream) ReadUntil(delim byte) []byte {
	start := s.pos
	for s.pos < len(s.buf) {
		if s.buf[s.pos] == delim {
			dst := make([]byte, s.pos-start)
			copy(dst, s.buf[start:s.pos])
			s.pos++
			return dst
		}
		s.pos++
	}
	s.err = io.EOF
	dst := make([]byte, s.pos-start)
	copy(dst, s.buf[start:s.pos])
	return dst
}

// --- 写入操作 ---

// ensure 确保缓冲区容量足够
func (s *Stream) ensure(n int) {
	if s.pos+n > cap(s.buf) {
		newCap := (s.pos + n) * 2
		if newCap < 64 {
			newCap = 64
		}
		newBuf := make([]byte, s.pos+n, newCap)
		copy(newBuf, s.buf)
		s.buf = newBuf
	}
	if s.pos+n > len(s.buf) {
		s.buf = s.buf[:s.pos+n]
	}
}

// Write 实现 io.Writer 接口，从当前位置覆盖写入（扩展缓冲区）
func (s *Stream) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.ensure(len(p))
	copy(s.buf[s.pos:], p)
	n = len(p)
	s.pos += n
	return n, nil
}

// WriteByte 写入一个字节
func (s *Stream) WriteByte(b byte) *Stream {
	s.ensure(1)
	s.buf[s.pos] = b
	s.pos++
	return s
}

// WriteBytes 写入字节切片
func (s *Stream) WriteBytes(data []byte) *Stream {
	if len(data) == 0 {
		return s
	}
	s.ensure(len(data))
	copy(s.buf[s.pos:], data)
	s.pos += len(data)
	return s
}

// WriteString 写入字符串
func (s *Stream) WriteString(str string) *Stream {
	return s.WriteBytes([]byte(str))
}

// WriteUint8 写入 uint8
func (s *Stream) WriteUint8(v uint8) *Stream {
	return s.WriteByte(v)
}

// WriteUint16 写入 uint16（使用当前字节序）
func (s *Stream) WriteUint16(v uint16) *Stream {
	tmp := make([]byte, 2)
	s.bo.PutUint16(tmp, v)
	return s.WriteBytes(tmp)
}

// WriteUint32 写入 uint32（使用当前字节序）
func (s *Stream) WriteUint32(v uint32) *Stream {
	tmp := make([]byte, 4)
	s.bo.PutUint32(tmp, v)
	return s.WriteBytes(tmp)
}

// WriteUint64 写入 uint64（使用当前字节序）
func (s *Stream) WriteUint64(v uint64) *Stream {
	tmp := make([]byte, 8)
	s.bo.PutUint64(tmp, v)
	return s.WriteBytes(tmp)
}

// WriteInt8 写入 int8
func (s *Stream) WriteInt8(v int8) *Stream {
	return s.WriteByte(byte(v))
}

// WriteInt16 写入 int16（使用当前字节序）
func (s *Stream) WriteInt16(v int16) *Stream {
	return s.WriteUint16(uint16(v))
}

// WriteInt32 写入 int32（使用当前字节序）
func (s *Stream) WriteInt32(v int32) *Stream {
	return s.WriteUint32(uint32(v))
}

// WriteInt64 写入 int64（使用当前字节序）
func (s *Stream) WriteInt64(v int64) *Stream {
	return s.WriteUint64(uint64(v))
}

// WriteFloat32 写入 float32（IEEE 754，使用当前字节序）
func (s *Stream) WriteFloat32(v float32) *Stream {
	return s.WriteUint32(math.Float32bits(v))
}

// WriteFloat64 写入 float64（IEEE 754，使用当前字节序）
func (s *Stream) WriteFloat64(v float64) *Stream {
	return s.WriteUint64(math.Float64bits(v))
}

// WriteVarint 写入变长有符号整数（Binary Varint / Protobuf ZigZag 编码）
func (s *Stream) WriteVarint(v int64) *Stream {
	uval := uint64(v)<<1 ^ uint64(v>>63)
	return s.WriteUvarint(uval)
}

// WriteUvarint 写入变长无符号整数
func (s *Stream) WriteUvarint(v uint64) *Stream {
	tmp := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(tmp, v)
	return s.WriteBytes(tmp[:n])
}

// WriteBool 写入布尔值（1 字节，true=1, false=0）
func (s *Stream) WriteBool(v bool) *Stream {
	if v {
		return s.WriteByte(1)
	}
	return s.WriteByte(0)
}

// WriteZero 写入 n 个零字节
func (s *Stream) WriteZero(n int) *Stream {
	tmp := make([]byte, n)
	return s.WriteBytes(tmp)
}

// WriteRepeat 重复写入某个字节 n 次
func (s *Stream) WriteRepeat(b byte, n int) *Stream {
	tmp := make([]byte, n)
	for i := range tmp {
		tmp[i] = b
	}
	return s.WriteBytes(tmp)
}

// --- 文件操作 ---

// SaveToFile 将 Stream 内容保存到文件
func (s *Stream) SaveToFile(path string) error {
	if err := os.WriteFile(path, s.buf, 0644); err != nil {
		return fmt.Errorf("binary_stream: write file %s: %w", path, err)
	}
	return nil
}

// LoadFromFile 从文件加载数据到 Stream（重置 Stream）
func (s *Stream) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("binary_stream: read file %s: %w", path, err)
	}
	s.Reset()
	s.WriteBytes(data)
	s.SetPos(0)
	return nil
}

// AppendToFile 将 Stream 内容追加到文件末尾
func (s *Stream) AppendToFile(path string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("binary_stream: append file %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(s.buf); err != nil {
		return fmt.Errorf("binary_stream: append file %s: %w", path, err)
	}
	return nil
}

// --- 编辑操作 ---

// Patch 在指定偏移处覆盖写入数据（定长，严格边界检查）
func (s *Stream) Patch(offset int, data []byte) *Stream {
	if offset < 0 || offset+len(data) > len(s.buf) {
		s.err = fmt.Errorf("binary_stream: patch out of range")
		return s
	}
	copy(s.buf[offset:], data)
	return s
}

// Replace 在指定范围内替换数据（可不同长度）
func (s *Stream) Replace(start, end int, data []byte) *Stream {
	if start < 0 || end > len(s.buf) || start > end {
		s.err = fmt.Errorf("binary_stream: replace out of range")
		return s
	}
	insertLen := len(data)
	oldLen := end - start
	diff := insertLen - oldLen

	if diff == 0 {
		copy(s.buf[start:end], data)
	} else if diff > 0 {
		newBuf := make([]byte, len(s.buf)+diff)
		copy(newBuf, s.buf[:start])
		copy(newBuf[start:], data)
		copy(newBuf[start+insertLen:], s.buf[end:])
		s.buf = newBuf
	} else {
		copy(s.buf[start:], data)
		copy(s.buf[start+insertLen:], s.buf[end:])
		s.buf = s.buf[:len(s.buf)+diff]
	}
	return s
}

// Insert 在指定位置插入数据（推挤后续数据）
func (s *Stream) Insert(offset int, data []byte) *Stream {
	return s.Replace(offset, offset, data)
}

// Delete 删除指定范围的数据
func (s *Stream) Delete(start, end int) *Stream {
	return s.Replace(start, end, nil)
}

// Truncate 截断 Stream 到指定长度
func (s *Stream) Truncate(length int) *Stream {
	if length < 0 {
		length = 0
	}
	if length < len(s.buf) {
		s.buf = s.buf[:length]
	}
	if s.pos > length {
		s.pos = length
	}
	return s
}

// HexDump 返回十六进制转储字符串
func (s *Stream) HexDump() string {
	result := ""
	for i, b := range s.buf {
		if i > 0 && i%16 == 0 {
			result += "\n"
		} else if i > 0 {
			result += " "
		}
		result += fmt.Sprintf("%02X", b)
	}
	return result
}