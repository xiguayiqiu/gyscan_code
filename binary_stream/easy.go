package binary_stream

import (
	"encoding/binary"
	"fmt"
	"os"
)

// --- 文件生成 ---

// CreateFile 通过二进制数据生成文件
func CreateFile(path string, data []byte) error {
	return NewFromBytes(data).SaveToFile(path)
}

// CreateFileFromStream 通过 Stream 生成文件
func CreateFileFromStream(path string, s *Stream) error {
	return s.SaveToFile(path)
}

// GenerateFile 通过链式构建二进制数据并生成文件
func GenerateFile(path string, buildFn func(s *Stream)) error {
	s := New()
	buildFn(s)
	return s.SaveToFile(path)
}

// --- 文件读取 ---

// ReadFile 读取文件为 Stream
func ReadFile(path string) (*Stream, error) {
	return NewFromFile(path)
}

// ReadFileBytes 读取文件为字节切片
func ReadFileBytes(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("binary_stream: read file %s: %w", path, err)
	}
	return data, nil
}

// --- 文件编辑 ---

// EditFile 读取文件，执行编辑函数后保存
func EditFile(path string, editFn func(s *Stream)) error {
	s, err := NewFromFile(path)
	if err != nil {
		return err
	}
	editFn(s)
	return s.SaveToFile(path)
}

// PatchFile 在文件指定偏移处覆盖写入
func PatchFile(path string, offset int, data []byte) error {
	return EditFile(path, func(s *Stream) {
		s.Patch(offset, data)
	})
}

// ReplaceInFile 在文件指定范围内替换数据
func ReplaceInFile(path string, start, end int, data []byte) error {
	return EditFile(path, func(s *Stream) {
		s.Replace(start, end, data)
	})
}

// InsertIntoFile 在文件指定位置插入数据
func InsertIntoFile(path string, offset int, data []byte) error {
	return EditFile(path, func(s *Stream) {
		s.Insert(offset, data)
	})
}

// DeleteFromFile 从文件删除指定范围的数据
func DeleteFromFile(path string, start, end int) error {
	return EditFile(path, func(s *Stream) {
		s.Delete(start, end)
	})
}

// TruncateFile 截断文件到指定长度
func TruncateFile(path string, length int) error {
	return EditFile(path, func(s *Stream) {
		s.Truncate(length)
	})
}

// --- 二进制数据构建 ---

// Build 构建二进制数据
func Build(buildFn func(s *Stream)) *Stream {
	s := New()
	buildFn(s)
	return s
}

// BuildBytes 构建二进制数据并返回字节切片
func BuildBytes(buildFn func(s *Stream)) []byte {
	return Build(buildFn).Bytes()
}

// BuildToFile 构建二进制数据并保存到文件
func BuildToFile(path string, buildFn func(s *Stream)) error {
	return GenerateFile(path, buildFn)
}

// --- 字节序快捷设置 ---

// NewBE 创建大端字节序的 Stream
func NewBE() *Stream {
	return NewWithOrder(binary.BigEndian)
}

// NewLE 创建小端字节序的 Stream
func NewLE() *Stream {
	return NewWithOrder(binary.LittleEndian)
}

// --- 文件信息 ---

// FileSize 获取文件大小
func FileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("binary_stream: stat file %s: %w", path, err)
	}
	return info.Size(), nil
}

// FileExists 判断文件是否存在
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// --- 比较 ---

// Compare 比较两个字节切片是否相等
func Compare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// CompareFiles 比较两个文件是否相同
func CompareFiles(path1, path2 string) (bool, error) {
	data1, err := os.ReadFile(path1)
	if err != nil {
		return false, fmt.Errorf("binary_stream: read %s: %w", path1, err)
	}
	data2, err := os.ReadFile(path2)
	if err != nil {
		return false, fmt.Errorf("binary_stream: read %s: %w", path2, err)
	}
	return Compare(data1, data2), nil
}

// --- 合并 ---

// MergeStreams 合并多个 Stream
func MergeStreams(streams ...*Stream) *Stream {
	s := New()
	for _, st := range streams {
		s.WriteBytes(st.buf)
	}
	return s
}

// MergeBytes 合并多个字节切片
func MergeBytes(chunks ...[]byte) []byte {
	s := New()
	for _, chunk := range chunks {
		s.WriteBytes(chunk)
	}
	return s.Bytes()
}