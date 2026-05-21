//go:build !opencl && !cuda
// +build !opencl,!cuda

package wifie

import "fmt"

func listGPUCrackDevices() []CrackDeviceGPUInfo {
	return nil
}

func startGPUCrack(cfg CrackConfig) (*CrackSession, error) {
	return nil, fmt.Errorf("wifie: GPU/OpenCL support not compiled in; rebuild with -tags opencl")
}

func gpuAvailable() bool {
	return false
}

func calcPMKBatchGPU(passwords [][]byte, essid []byte) ([][32]byte, error) {
	return nil, fmt.Errorf("wifie: GPU/OpenCL support not compiled in; rebuild with -tags opencl")
}