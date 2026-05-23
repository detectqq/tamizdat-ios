package wgturnclient

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultListen      = "127.0.0.1:9000"
	defaultWorkers     = workersPerGroup
	maxWorkers         = 72
	defaultVKAppID     = "6287487"
	defaultVKAppSecret = "QbYic1K3lEV5kTGiqlq2"
	defaultUserAgent   = "Mozilla/5.0"
)

type Config struct {
	Listen         string
	PeerAddr       string
	Workers        int
	UseUDP         bool
	UseTCP         bool
	VKHashes       []string
	SecondaryHash  string
	DeviceID       string
	ConnPassword   string
	VKAppID        string
	VKAppSecret    string
	UserAgent      string
	CaptchaMode    string
	NoDNS          bool
	PreloadedCreds *Credentials
	OnConfig       func(string)

	TurnHost    string
	TurnPort    string
	SNI         string
	SplitTunnel bool
}

type Runner struct {
	cfg Config

	vkAppID        atomic.Value
	vkAppSecret    atomic.Value
	captchaMode   atomic.Value
	noDNS          atomic.Bool
	userAgent      atomic.Value
	preloadedCreds atomic.Pointer[Credentials]

	captchaResultCh chan string
	vkSemaphore     chan struct{}
	captchaWVSem    chan struct{}

	cacheMutex         sync.Mutex
	cachedSuccessToken string
	cachedTokenUsages  int32
	groupAuthMutex     sync.Mutex

	pauseFlag int32

	runtimeMu sync.Mutex
	cancel    context.CancelFunc
	localConn net.PacketConn
}

func New(cfg Config) (*Runner, error) {
	cfg.Listen = strings.TrimSpace(cfg.Listen)
	if cfg.Listen == "" {
		cfg.Listen = defaultListen
	}
	cfg.PeerAddr = strings.TrimSpace(cfg.PeerAddr)
	cfg.SecondaryHash = strings.TrimSpace(cfg.SecondaryHash)
	cfg.DeviceID = strings.TrimSpace(cfg.DeviceID)
	if cfg.DeviceID == "" {
		cfg.DeviceID = "unknown"
	}
	cfg.VKAppID = strings.TrimSpace(cfg.VKAppID)
	if cfg.VKAppID == "" {
		cfg.VKAppID = defaultVKAppID
	}
	cfg.VKAppSecret = strings.TrimSpace(cfg.VKAppSecret)
	if cfg.VKAppSecret == "" {
		cfg.VKAppSecret = defaultVKAppSecret
	}
	cfg.CaptchaMode = strings.TrimSpace(cfg.CaptchaMode)
	if cfg.CaptchaMode == "" {
		cfg.CaptchaMode = "rjs"
	}
	cfg.UserAgent = strings.TrimSpace(cfg.UserAgent)
	if cfg.UserAgent == "" {
		cfg.UserAgent = defaultUserAgent
	}
	if !cfg.UseTCP && !cfg.UseUDP {
		cfg.UseTCP = true
	}
	cfg.Workers = normalizeWorkerCount(cfg.Workers)
	cfg.VKHashes = normalizeHashes(cfg.VKHashes)
	if len(cfg.VKHashes) == 0 && cfg.PreloadedCreds != nil {
		cfg.VKHashes = []string{"preloaded"}
	}
	if cfg.PeerAddr == "" || len(cfg.VKHashes) == 0 {
		return nil, fmt.Errorf("нужны PeerAddr и VKHashes")
	}

	r := &Runner{
		cfg:             cfg,
		captchaResultCh: make(chan string, 1),
		vkSemaphore:     make(chan struct{}, 2),
		captchaWVSem:    make(chan struct{}, 1),
	}
	r.vkAppID.Store(cfg.VKAppID)
	r.vkAppSecret.Store(cfg.VKAppSecret)
	r.captchaMode.Store(cfg.CaptchaMode)
	r.userAgent.Store(cfg.UserAgent)
	r.noDNS.Store(cfg.NoDNS)
	if cfg.PreloadedCreds != nil {
		dup := *cfg.PreloadedCreds
		dup.TurnURLs = append([]string(nil), cfg.PreloadedCreds.TurnURLs...)
		r.preloadedCreds.Store(&dup)
	}
	return r, nil
}

func (r *Runner) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	if err := r.setRuntime(cancel, nil); err != nil {
		cancel()
		return err
	}
	defer func() {
		cancel()
		r.clearRuntime()
	}()

	peer, err := net.ResolveUDPAddr("udp", r.cfg.PeerAddr)
	if err != nil {
		return fmt.Errorf("ошибка разбора пира: %w", err)
	}

	tp := &TurnParams{
		Host:          r.cfg.TurnHost,
		Port:          r.cfg.TurnPort,
		Hashes:        r.cfg.VKHashes,
		SecondaryHash: r.cfg.SecondaryHash,
		Sni:           r.cfg.SNI,
	}

	localConn, err := net.ListenPacket("udp", r.cfg.Listen)
	if err != nil {
		return fmt.Errorf("ошибка слушателя %s: %w", r.cfg.Listen, err)
	}
	r.setLocalConn(localConn)
	defer localConn.Close()
	if uc, ok := localConn.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(socketBufSize)
		_ = uc.SetWriteBuffer(socketBufSize)
	}
	stopLocalConn := context.AfterFunc(runCtx, func() { _ = localConn.Close() })
	defer stopLocalConn()

	_, localPort, _ := net.SplitHostPort(r.cfg.Listen)
	if localPort == "" {
		localPort = "9000"
	}

	numGroups := r.cfg.Workers / workersPerGroup

	log.Println("[КЛИЕНТ] ═══════════════════════════════════════")
	log.Printf("[КЛИЕНТ] VK App: %s", r.cfg.VKAppID)
	log.Printf("[КЛИЕНТ] Воркеров: %d (групп: %d, по %d)", r.cfg.Workers, numGroups, workersPerGroup)
	log.Printf("[КЛИЕНТ] Хешей: %d", len(r.cfg.VKHashes))
	log.Printf("[КЛИЕНТ] Слушаю: %s | Пир: %s", r.cfg.Listen, r.cfg.PeerAddr)
	proto := "TCP"
	if r.cfg.UseUDP {
		proto = "UDP"
	}
	log.Printf("[КЛИЕНТ] Протокол: %s", proto)
	log.Printf("[КЛИЕНТ] Device ID: %s", r.cfg.DeviceID)
	log.Printf("[КЛИЕНТ] Обход капчи: %s", r.getCaptchaMode())
	log.Println("[КЛИЕНТ] ═══════════════════════════════════════")

	stats := NewStats()
	shutdownCh := make(chan struct{})
	go func() {
		<-runCtx.Done()
		close(shutdownCh)
	}()
	go stats.RunLoop(shutdownCh)

	disp := NewDispatcher(runCtx, localConn, stats)
	defer disp.Shutdown()

	configCh := make(chan string, 1)
	configDone := make(chan struct{})
	go func() {
		defer close(configDone)
		select {
		case rawConf, ok := <-configCh:
			if !ok || rawConf == "" {
				return
			}
			finalConf := ensureConfigMTU(rawConf)
			if r.cfg.SplitTunnel {
				finalConf = ModifyConfigForSplitTunnel(finalConf, peer.IP)
			}
			if r.cfg.OnConfig != nil {
				r.cfg.OnConfig(finalConf)
			}
		case <-runCtx.Done():
		}
	}()

	var wg sync.WaitGroup
	workerIDCounter := 1
	var prevWaitReady <-chan struct{}

	for g := 0; g < numGroups; g++ {
		isFirst := g == 0

		var myWaitReady <-chan struct{}
		var mySignalReady chan<- struct{}

		if g > 0 {
			myWaitReady = prevWaitReady
		}
		if g < numGroups-1 {
			ch := make(chan struct{})
			mySignalReady = ch
			prevWaitReady = ch
		}

		ids := make([]int, workersPerGroup)
		for i := range ids {
			ids[i] = workerIDCounter
			workerIDCounter++
		}

		gID := g + 1
		cycle := time.Duration(defaultCycleSecs) * time.Second
		var cc chan<- string
		if isFirst {
			cc = configCh
		}

		wg.Add(1)
		go func(groupID int, cycleDir time.Duration, isFirstGroup bool, configChan chan<- string, workerIDs []int, startHashIndex int, waitR <-chan struct{}, sigR chan<- struct{}) {
			defer wg.Done()
			r.workerGroup(runCtx, groupID, startHashIndex, tp, peer, disp, localPort, r.cfg.UseUDP,
				isFirstGroup, configChan, workerIDs, cycleDir, &r.pauseFlag, r.cfg.DeviceID, r.cfg.ConnPassword, stats, waitR, sigR)
		}(gID, cycle, isFirst, cc, ids, g, myWaitReady, mySignalReady)
	}

	wg.Wait()
	close(configCh)
	<-configDone
	log.Println("[КЛИЕНТ] Все воркеры завершены")
	return nil
}

func (r *Runner) Shutdown() {
	r.runtimeMu.Lock()
	cancel := r.cancel
	localConn := r.localConn
	r.runtimeMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if localConn != nil {
		_ = localConn.Close()
	}
}

func (r *Runner) SetPaused(paused bool) {
	if paused {
		atomic.StoreInt32(&r.pauseFlag, 1)
		return
	}
	atomic.StoreInt32(&r.pauseFlag, 0)
}

func (r *Runner) SubmitCaptchaResult(result string) {
	r.drainCaptchaResult()
	r.captchaResultCh <- result
}

func (r *Runner) drainCaptchaResult() {
	select {
	case <-r.captchaResultCh:
	default:
	}
}

func (r *Runner) setRuntime(cancel context.CancelFunc, localConn net.PacketConn) error {
	r.runtimeMu.Lock()
	defer r.runtimeMu.Unlock()
	if r.cancel != nil {
		return fmt.Errorf("runner already started")
	}
	r.cancel = cancel
	r.localConn = localConn
	return nil
}

func (r *Runner) setLocalConn(localConn net.PacketConn) {
	r.runtimeMu.Lock()
	r.localConn = localConn
	r.runtimeMu.Unlock()
}

func (r *Runner) clearRuntime() {
	r.runtimeMu.Lock()
	r.cancel = nil
	r.localConn = nil
	r.runtimeMu.Unlock()
}

func normalizeWorkerCount(n int) int {
	if n <= 0 {
		n = defaultWorkers
	}
	if n > maxWorkers {
		n = maxWorkers
	}
	if n < workersPerGroup {
		n = workersPerGroup
	}
	return (n / workersPerGroup) * workersPerGroup
}

func normalizeHashes(hashes []string) []string {
	result := make([]string, 0, len(hashes))
	for _, hash := range hashes {
		hash = strings.TrimSpace(hash)
		if hash != "" {
			result = append(result, hash)
		}
	}
	return result
}

func ensureConfigMTU(conf string) string {
	if strings.Contains(conf, "MTU =") {
		return conf
	}
	lines := strings.Split(conf, "\n")
	newLines := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		newLines = append(newLines, line)
		if strings.TrimSpace(line) == "[Interface]" {
			newLines = append(newLines, "MTU = 1280")
		}
	}
	return strings.Join(newLines, "\n")
}
