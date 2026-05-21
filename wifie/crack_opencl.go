//go:build opencl && !cuda
// +build opencl,!cuda

package wifie

/*
#cgo LDFLAGS: -lOpenCL

#include <stdlib.h>
#include <CL/cl.h>

static cl_int getPlatformCount(cl_uint *count) {
	return clGetPlatformIDs(0, NULL, count);
}

static cl_int getPlatforms(cl_platform_id *platforms, cl_uint count) {
	return clGetPlatformIDs(count, platforms, NULL);
}

static cl_int getPlatformInfo(cl_platform_id platform, cl_platform_info param, char *buf, size_t bufSize) {
	return clGetPlatformInfo(platform, param, bufSize, buf, NULL);
}

static cl_int getDeviceCount(cl_platform_id platform, cl_uint *count) {
	return clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 0, NULL, count);
}

static cl_int getDevices(cl_platform_id platform, cl_device_id *devices, cl_uint count) {
	return clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, count, devices, NULL);
}

static cl_int getDeviceInfoInt(cl_device_id device, cl_device_info param, cl_uint *val) {
	return clGetDeviceInfo(device, param, sizeof(cl_uint), val, NULL);
}

static cl_int getDeviceInfoUlong(cl_device_id device, cl_device_info param, cl_ulong *val) {
	return clGetDeviceInfo(device, param, sizeof(cl_ulong), val, NULL);
}

static cl_int getDeviceInfoString(cl_device_id device, cl_device_info param, char *buf, size_t bufSize) {
	return clGetDeviceInfo(device, param, bufSize, buf, NULL);
}

static cl_int getDeviceInfoSize(cl_device_id device, cl_device_info param, size_t *size) {
	return clGetDeviceInfo(device, param, sizeof(size_t), size, NULL);
}
*/
import "C"

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

func listGPUCrackDevices() []CrackDeviceGPUInfo {
	var platformCount C.cl_uint
	if C.getPlatformCount(&platformCount) != C.CL_SUCCESS || platformCount == 0 {
		return nil
	}

	platforms := make([]C.cl_platform_id, platformCount)
	if C.getPlatforms(&platforms[0], platformCount) != C.CL_SUCCESS {
		return nil
	}

	var devices []CrackDeviceGPUInfo
	idx := 0

	for _, platform := range platforms {
		var devCount C.cl_uint
		if C.getDeviceCount(platform, &devCount) != C.CL_SUCCESS || devCount == 0 {
			continue
		}

		clDevices := make([]C.cl_device_id, devCount)
		if C.getDevices(platform, &clDevices[0], devCount) != C.CL_SUCCESS {
			continue
		}

		for _, dev := range clDevices {
			info := CrackDeviceGPUInfo{Index: idx}
			idx++

			var buf [256]byte
			if C.getDeviceInfoString(dev, C.CL_DEVICE_NAME, (*C.char)(unsafe.Pointer(&buf[0])), 256) == C.CL_SUCCESS {
				info.Name = string(buf[:clen(buf[:])])
			}

			if C.getDeviceInfoString(dev, C.CL_DEVICE_VENDOR, (*C.char)(unsafe.Pointer(&buf[0])), 256) == C.CL_SUCCESS {
				info.Vendor = string(buf[:clen(buf[:])])
			}

			var mem C.cl_ulong
			if C.getDeviceInfoUlong(dev, C.CL_DEVICE_GLOBAL_MEM_SIZE, &mem) == C.CL_SUCCESS {
				info.MemoryMB = uint64(mem) / 1024 / 1024
			}

			var cu C.cl_uint
			if C.getDeviceInfoInt(dev, C.CL_DEVICE_MAX_COMPUTE_UNITS, &cu) == C.CL_SUCCESS {
				info.ComputeUnits = int(cu)
			}

			var mwg C.size_t
			if C.getDeviceInfoSize(dev, C.CL_DEVICE_MAX_WORK_GROUP_SIZE, &mwg) == C.CL_SUCCESS {
				info.MaxWorkGroup = int(mwg)
			}

			devices = append(devices, info)
		}
	}

	return devices
}

func clen(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return len(b)
}

func startGPUCrack(cfg CrackConfig) (*CrackSession, error) {
	if cfg.Workers <= 0 {
		cfg.Workers = runtime.NumCPU()
	}

	session := &CrackSession{
		config:    cfg,
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
		startTime: time.Now(),
	}

	go session.runGPU()

	return session, nil
}

func (s *CrackSession) runGPU() {
	defer close(s.doneCh)

	gpuInfo := ListGPUCrackDevices()
	if len(gpuInfo) == 0 {
		s.run()
		return
	}

	deviceCount := len(gpuInfo)
	if deviceCount > s.config.Workers {
		deviceCount = s.config.Workers
	}

	passCh := make(chan string, deviceCount*32)
	var wg sync.WaitGroup

	for i := 0; i < deviceCount; i++ {
		wg.Add(1)
		go s.gpuWorker(i, i%len(gpuInfo), passCh, &wg)
	}

	for i := 0; i < s.config.Workers-deviceCount; i++ {
		wg.Add(1)
		go s.worker(i, passCh, &wg)
	}

	s.readWordlist(passCh)
	close(passCh)
	wg.Wait()
}

func (s *CrackSession) gpuWorker(id, gpuIdx int, passCh <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	td := s.buildTargetData()

	batch := make([]string, 0, 128)

	for {
		select {
		case <-s.stopCh:
			s.processBatchFast(batch, td)
			return
		case pass, ok := <-passCh:
			if !ok {
				s.processBatchFast(batch, td)
				return
			}
			batch = append(batch, pass)
			if len(batch) >= 128 {
				s.processBatchFast(batch, td)
				batch = batch[:0]
			}
		}
	}
}

func cleanOpenCL() {
}

func initOpenCLResources() error {
	return fmt.Errorf("wifie: OpenCL kernel compilation not yet implemented; use CPU mode or hashcat")
}

func gpuAvailable() bool {
	return len(ListGPUCrackDevices()) > 0
}

func calcPMKBatchGPU(passwords [][]byte, essid []byte) ([][32]byte, error) {
	results := make([][32]byte, len(passwords))
	for i, p := range passwords {
		results[i] = CalcPMK(p, essid)
	}
	return results, nil
}

// OpenCL kernel source for PBKDF2-SHA1 PMK computation
const openclPMKKernelSource = `
// PBKDF2-SHA1 based PMK computation for WPA/WPA2
// Based on aircrack-ng's implementation

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20
#define PMK_LENGTH 32
#define PBKDF2_ITERATIONS 4096

typedef struct {
    uint h[5];
    uint len_low;
    uint len_high;
    uchar buffer[SHA1_BLOCK_SIZE];
} sha1_ctx;

#define SHA1_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

void sha1_transform(uint *state, const uchar *block) {
    uint w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint)block[i*4] << 24) | ((uint)block[i*4+1] << 16) |
               ((uint)block[i*4+2] << 8) | (uint)block[i*4+3];
    for (int i = 16; i < 80; i++)
        w[i] = SHA1_ROTL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

    uint a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];

    for (int i = 0; i < 80; i++) {
        uint f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }

        uint temp = SHA1_ROTL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = SHA1_ROTL(b, 30); b = a; a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

void sha1_hmac(const uchar *key, int key_len, const uchar *data, int data_len, uchar *digest) {
    uchar key_block[SHA1_BLOCK_SIZE];
    uchar ipad[SHA1_BLOCK_SIZE], opad[SHA1_BLOCK_SIZE];

    for (int i = 0; i < SHA1_BLOCK_SIZE; i++) {
        key_block[i] = (i < key_len) ? key[i] : 0;
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    uint state[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    uchar padded_block[SHA1_BLOCK_SIZE];

    for (int i = 0; i < SHA1_BLOCK_SIZE; i++) padded_block[i] = ipad[i];
    for (int i = 0; i < data_len; i++) padded_block[i] ^= data[i];
    sha1_transform(state, padded_block);

    // padding
    uint bit_len = (SHA1_BLOCK_SIZE + data_len) * 8;
    uchar final_block[SHA1_BLOCK_SIZE];
    for (int i = 0; i < SHA1_BLOCK_SIZE - data_len; i++) final_block[i] = 0;
    final_block[0] = 0x80;
    sha1_transform(state, final_block);

    for (int i = 0; i < 5; i++) {
        digest[i*4] = (state[i] >> 24) & 0xFF;
        digest[i*4+1] = (state[i] >> 16) & 0xFF;
        digest[i*4+2] = (state[i] >> 8) & 0xFF;
        digest[i*4+3] = state[i] & 0xFF;
    }

    // outer hash
    state[0] = 0x67452301; state[1] = 0xEFCDAB89;
    state[2] = 0x98BADCFE; state[3] = 0x10325476; state[4] = 0xC3D2E1F0;

    for (int i = 0; i < SHA1_BLOCK_SIZE; i++) padded_block[i] = opad[i];
    for (int i = 0; i < SHA1_DIGEST_SIZE; i++) padded_block[i] ^= digest[i];
    sha1_transform(state, padded_block);

    for (int i = 0; i < SHA1_DIGEST_SIZE - SHA1_DIGEST_SIZE; i++) final_block[i] = 0;
    final_block[0] = 0x80;
    sha1_transform(state, final_block);

    for (int i = 0; i < 5; i++) {
        digest[i*4] = (state[i] >> 24) & 0xFF;
        digest[i*4+1] = (state[i] >> 16) & 0xFF;
        digest[i*4+2] = (state[i] >> 8) & 0xFF;
        digest[i*4+3] = state[i] & 0xFF;
    }
}

__kernel void calc_pmk(__global const uchar *passwords,
                        __constant uint *pass_lens,
                        __constant uint *pass_offsets,
                        __global const uchar *essid,
                        uint essid_len,
                        __global uchar *pmks,
                        uint num_passwords) {
    uint idx = get_global_id(0);
    if (idx >= num_passwords) return;

    uchar salt[64];
    for (uint i = 0; i < essid_len; i++) salt[i] = essid[i];

    uint off = pass_offsets[idx];
    uint len = pass_lens[idx];

    uchar T[SHA1_DIGEST_SIZE];
    uchar U[SHA1_DIGEST_SIZE];
    uchar pmk[PMK_LENGTH];

    for (int block = 1; block <= 2; block++) {
        salt[essid_len] = (block >> 24) & 0xFF;
        salt[essid_len+1] = (block >> 16) & 0xFF;
        salt[essid_len+2] = (block >> 8) & 0xFF;
        salt[essid_len+3] = block & 0xFF;

        sha1_hmac(&passwords[off], len, salt, essid_len + 4, T);

        for (int i = 0; i < SHA1_DIGEST_SIZE; i++) U[i] = T[i];

        for (int iter = 1; iter < PBKDF2_ITERATIONS; iter++) {
            sha1_hmac(&passwords[off], len, U, SHA1_DIGEST_SIZE, U);
            for (int i = 0; i < SHA1_DIGEST_SIZE; i++) T[i] ^= U[i];
        }

        uint pmk_off = idx * PMK_LENGTH + (block - 1) * SHA1_DIGEST_SIZE;
        for (int i = 0; i < SHA1_DIGEST_SIZE; i++) {
            if (pmk_off + i < idx * PMK_LENGTH + PMK_LENGTH)
                pmks[pmk_off + i] = T[i];
        }
    }
}
`