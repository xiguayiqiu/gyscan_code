//go:build cuda
// +build cuda

package wifie

import (
	_ "embed"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/gocnn/gocu"
)

//go:embed crack_cuda.ptx
var ptxData string

type cudaEngine struct {
	device     gocu.Device
	ctx        *gocu.Context
	module     gocu.Module
	kernel     gocu.Function
	stream     *gocu.Stream
	maxThreads int
}

var (
	cudaOnce   sync.Once
	cudaEng    *cudaEngine
	cudaInitErr error
)

func initCUDAEngine() error {
	cudaOnce.Do(func() {
		count, err := gocu.DeviceGetCount()
		if err != nil || count == 0 {
			cudaInitErr = fmt.Errorf("wifie: no CUDA devices: %v", err)
			return
		}

		dev, err := gocu.DeviceGet(0)
		if err != nil {
			cudaInitErr = fmt.Errorf("wifie: CUDA DeviceGet: %w", err)
			return
		}

		ctx, err := gocu.CtxCreate(gocu.CuCtxSchedAuto, dev)
		if err != nil {
			cudaInitErr = fmt.Errorf("wifie: CUDA CtxCreate: %w", err)
			return
		}

		module, err := gocu.ModuleLoadData([]byte(ptxData))
		if err != nil {
			ctx.Destroy()
			cudaInitErr = fmt.Errorf("wifie: CUDA ModuleLoadData: %w", err)
			return
		}

		kernel, err := module.GetFunction("wpa_pbkdf2_pmk")
		if err != nil {
			module.Unload()
			ctx.Destroy()
			cudaInitErr = fmt.Errorf("wifie: CUDA GetFunction: %w", err)
			return
		}

		stream, err := gocu.StreamCreate(gocu.CuStreamDefault)
		if err != nil {
			module.Unload()
			ctx.Destroy()
			cudaInitErr = fmt.Errorf("wifie: CUDA StreamCreate: %w", err)
			return
		}

		maxThreads, _ := dev.Attribute(gocu.CuDeviceAttributeMaxBlockDimX)
		if maxThreads <= 0 {
			maxThreads = 256
		}

		cudaEng = &cudaEngine{
			device:     dev,
			ctx:        ctx,
			module:     module,
			kernel:     kernel,
			stream:     stream,
			maxThreads: maxThreads,
		}
	})
	return cudaInitErr
}

func gpuAvailable() bool {
	if err := initCUDAEngine(); err != nil {
		return false
	}
	return cudaEng != nil
}

func listGPUCrackDevices() []CrackDeviceGPUInfo {
	if err := initCUDAEngine(); err != nil {
		return nil
	}

	count, _ := gocu.DeviceGetCount()
	var devices []CrackDeviceGPUInfo

	for i := 0; i < count; i++ {
		dev, err := gocu.DeviceGet(i)
		if err != nil {
			continue
		}

		info := CrackDeviceGPUInfo{Index: i}

		name, _ := dev.Name()
		info.Name = name
		info.Vendor = "NVIDIA"

		mem, _ := dev.TotalMem()
		info.MemoryMB = uint64(mem) / 1024 / 1024

		mp, _ := dev.Attribute(gocu.CuDeviceAttributeMultiprocessorCount)
		info.ComputeUnits = mp

		mwg, _ := dev.Attribute(gocu.CuDeviceAttributeMaxBlockDimX)
		info.MaxWorkGroup = mwg

		devices = append(devices, info)
	}

	return devices
}

func startGPUCrack(cfg CrackConfig) (*CrackSession, error) {
	if err := initCUDAEngine(); err != nil {
		return nil, err
	}

	if cfg.Workers <= 0 {
		cfg.Workers = runtime.NumCPU()
	}

	session := &CrackSession{
		config:    cfg,
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
		startTime: time.Now(),
	}

	go session.runGPUHybrid()

	return session, nil
}

func (s *CrackSession) runGPUHybrid() {
	defer close(s.doneCh)

	passCh := make(chan string, s.config.Workers*32)
	var wg sync.WaitGroup

	wg.Add(1)
	go s.cudaWorker(passCh, &wg)

	for i := 0; i < s.config.Workers; i++ {
		wg.Add(1)
		go s.worker(i, passCh, &wg)
	}

	s.readWordlist(passCh)
	close(passCh)
	wg.Wait()
}

func (s *CrackSession) cudaWorker(passCh <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	batchSize := 1024
	batch := make([]string, 0, batchSize)

	for {
		select {
		case <-s.stopCh:
			s.processBatchFast(batch, s.buildTargetData())
			return
		case pass, ok := <-passCh:
			if !ok {
				s.processBatchFast(batch, s.buildTargetData())
				return
			}
			batch = append(batch, pass)
			if len(batch) >= batchSize {
				s.processCUDABatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (s *CrackSession) processCUDABatch(batch []string) {
	if len(batch) == 0 {
		return
	}

	td := s.buildTargetData()
	if len(td) == 0 {
		return
	}

	t := &td[0]
	essid := t.essid
	batchSize := len(batch)

	flatSize := 0
	passLens := make([]uint32, batchSize)
	passOffsets := make([]uint32, batchSize)

	for i, pass := range batch {
		passLens[i] = uint32(len(pass))
		passOffsets[i] = uint32(flatSize)
		flatSize += len(pass)
	}

	flatPasswords := make([]byte, flatSize)
	for i, pass := range batch {
		copy(flatPasswords[passOffsets[i]:], pass)
	}

	dPasswords, err := gocu.MemAlloc(int64(flatSize))
	if err != nil {
		s.processBatchFast(batch, td)
		return
	}
	defer dPasswords.Free()

	dPassLens, err := gocu.MemAlloc(int64(batchSize * 4))
	if err != nil {
		s.processBatchFast(batch, td)
		return
	}
	defer dPassLens.Free()

	dPassOffsets, err := gocu.MemAlloc(int64(batchSize * 4))
	if err != nil {
		s.processBatchFast(batch, td)
		return
	}
	defer dPassOffsets.Free()

	dESSID, err := gocu.MemAlloc(int64(len(essid)))
	if err != nil {
		s.processBatchFast(batch, td)
		return
	}
	defer dESSID.Free()

	pmkSize := int64(batchSize * 32)
	dPMKs, err := gocu.MemAlloc(pmkSize)
	if err != nil {
		s.processBatchFast(batch, td)
		return
	}
	defer dPMKs.Free()

	gocu.MemcpyHtoD(dPasswords, unsafe.Pointer(&flatPasswords[0]), int64(flatSize))
	gocu.MemcpyHtoD(dPassLens, unsafe.Pointer(&passLens[0]), int64(batchSize*4))
	gocu.MemcpyHtoD(dPassOffsets, unsafe.Pointer(&passOffsets[0]), int64(batchSize*4))
	gocu.MemcpyHtoD(dESSID, unsafe.Pointer(&essid[0]), int64(len(essid)))

	blockSize := uint32(cudaEng.maxThreads)
	if blockSize > 1024 {
		blockSize = 1024
	}
	gridSize := uint32((batchSize + int(blockSize) - 1) / int(blockSize))

	kernelParams := []unsafe.Pointer{
		unsafe.Pointer(&dPasswords),
		unsafe.Pointer(&dPassLens),
		unsafe.Pointer(&dPassOffsets),
		unsafe.Pointer(&dESSID),
	}
	essidLen := uint32(len(essid))
	numPass := uint32(batchSize)
	kernelParams = append(kernelParams,
		unsafe.Pointer(&essidLen),
		unsafe.Pointer(&dPMKs),
		unsafe.Pointer(&numPass),
	)

	err = cudaEng.kernel.Launch(
		gridSize, 1, 1,
		blockSize, 1, 1,
		0, *cudaEng.stream,
		kernelParams, nil,
	)
	if err != nil {
		cudaEng.ctx.Synchronize()
		s.processBatchFast(batch, td)
		return
	}

	cudaEng.stream.Synchronize()

	pmks := make([]byte, pmkSize)
	gocu.MemcpyDtoH(unsafe.Pointer(&pmks[0]), dPMKs, pmkSize)

	for i, pass := range batch {
		select {
		case <-s.stopCh:
			return
		default:
		}

		var pmk [32]byte
		copy(pmk[:], pmks[i*32:(i+1)*32])

		if t.eapolSize > 0 && len(t.mic) > 0 {
			ptk := CalcPTKWithData(pmk[:], t.pkeData, t.keyVer)
			mic, err := CalcEAPOLMIC(t.eapolData[:t.eapolSize], ptk, t.keyVer)
			if err == nil {
				found := true
				for j := 0; j < 16 && j < len(mic) && j < len(t.mic); j++ {
					if mic[j] != t.mic[j] {
						found = false
						break
					}
				}
				if found {
					result := CrackResult{
						BSSID:      t.bssid,
						ESSID:      string(t.essid),
						STAMAC:     t.stamac,
						Passphrase: pass,
						FoundAt:    time.Now(),
						Elapsed:    time.Since(s.startTime),
						Tried:      atomic.LoadUint64(&s.tried),
						Method:     "handshake",
					}
					copy(result.PMK[:], pmk[:])
					result.PTK = ptk
					result.MIC = t.mic

					s.mu.Lock()
					s.results = append(s.results, result)
					s.mu.Unlock()
					atomic.AddInt32(&s.found, 1)

					if len(td) == 1 {
						s.Stop()
						return
					}
				}
			}
		}

		atomic.AddUint64(&s.tried, 1)
	}
}

func calcPMKBatchGPU(passwords [][]byte, essid []byte) ([][32]byte, error) {
	if err := initCUDAEngine(); err != nil {
		results := make([][32]byte, len(passwords))
		for i, p := range passwords {
			results[i] = CalcPMK(p, essid)
		}
		return results, nil
	}

	batchSize := len(passwords)

	flatSize := 0
	passLens := make([]uint32, batchSize)
	passOffsets := make([]uint32, batchSize)
	for i, p := range passwords {
		passLens[i] = uint32(len(p))
		passOffsets[i] = uint32(flatSize)
		flatSize += len(p)
	}

	flatPasswords := make([]byte, flatSize)
	for i, p := range passwords {
		copy(flatPasswords[passOffsets[i]:], p)
	}

	dPasswords, _ := gocu.MemAlloc(int64(flatSize))
	defer dPasswords.Free()
	dPassLens, _ := gocu.MemAlloc(int64(batchSize * 4))
	defer dPassLens.Free()
	dPassOffsets, _ := gocu.MemAlloc(int64(batchSize * 4))
	defer dPassOffsets.Free()
	dESSID, _ := gocu.MemAlloc(int64(len(essid)))
	defer dESSID.Free()
	dPMKs, _ := gocu.MemAlloc(int64(batchSize * 32))
	defer dPMKs.Free()

	gocu.MemcpyHtoD(dPasswords, unsafe.Pointer(&flatPasswords[0]), int64(flatSize))
	gocu.MemcpyHtoD(dPassLens, unsafe.Pointer(&passLens[0]), int64(batchSize*4))
	gocu.MemcpyHtoD(dPassOffsets, unsafe.Pointer(&passOffsets[0]), int64(batchSize*4))
	gocu.MemcpyHtoD(dESSID, unsafe.Pointer(&essid[0]), int64(len(essid)))

	blockSize := uint32(cudaEng.maxThreads)
	if blockSize > 1024 {
		blockSize = 1024
	}
	gridSize := uint32((batchSize + int(blockSize) - 1) / int(blockSize))

	essidLen := uint32(len(essid))
	numPass := uint32(batchSize)

	kernelParams := []unsafe.Pointer{
		unsafe.Pointer(&dPasswords),
		unsafe.Pointer(&dPassLens),
		unsafe.Pointer(&dPassOffsets),
		unsafe.Pointer(&dESSID),
		unsafe.Pointer(&essidLen),
		unsafe.Pointer(&dPMKs),
		unsafe.Pointer(&numPass),
	}

	cudaEng.kernel.Launch(
		gridSize, 1, 1,
		blockSize, 1, 1,
		0, *cudaEng.stream,
		kernelParams, nil,
	)
	cudaEng.stream.Synchronize()

	pmks := make([]byte, batchSize*32)
	gocu.MemcpyDtoH(unsafe.Pointer(&pmks[0]), dPMKs, int64(batchSize*32))

	results := make([][32]byte, batchSize)
	for i := range results {
		copy(results[i][:], pmks[i*32:(i+1)*32])
	}

	return results, nil
}