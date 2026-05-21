package wifie

// CrackDeviceGPUInfo 获取系统可用的 GPU 设备信息
type CrackDeviceGPUInfo struct {
	Index       int
	Name        string
	Vendor      string
	MemoryMB    uint64
	ComputeUnits int
	MaxWorkGroup int
}

// ListGPUCrackDevices 列出可用的 GPU 破解设备
// 如果编译时不带 opencl 标签则返回空
func ListGPUCrackDevices() []CrackDeviceGPUInfo {
	return listGPUCrackDevices()
}

// StartGPUCrack 使用 GPU 启动 WPA 破解
// 需要编译时指定 opencl 标签：go build -tags opencl
func StartGPUCrack(cfg CrackConfig) (*CrackSession, error) {
	return startGPUCrack(cfg)
}

// GpuAvailable 检查 GPU 是否可用（无 opencl 标签时总是返回 false）
func GpuAvailable() bool {
	return gpuAvailable()
}

// CalcPMKBatchGPU 批量计算 PMK，使用 GPU 加速
func CalcPMKBatchGPU(passwords [][]byte, essid []byte) ([][32]byte, error) {
	return calcPMKBatchGPU(passwords, essid)
}