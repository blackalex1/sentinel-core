package supervisor

import (
	"fmt"
	"sync"
	"time"
)

// Controller manages core processes, telemetry, and operations
type Controller struct {
	mu            sync.RWMutex
	startTime     time.Time
	clashAPIAddr  string
	hysteriaPorts []int
	logPaths      map[string]string
}

var (
	defaultController *Controller
	once              sync.Once
)

// GetController returns the singleton supervisor Controller
func GetController() *Controller {
	once.Do(func() {
		defaultController = &Controller{
			startTime:     time.Now(),
			clashAPIAddr:  "127.0.0.1:9090",
			hysteriaPorts: []int{10100, 10101, 10102},
			logPaths:      make(map[string]string),
		}
	})
	return defaultController
}

// Configure sets endpoints and log paths
func (c *Controller) Configure(clashAddr string, hysteriaPorts []int, logPaths map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if clashAddr != "" {
		c.clashAPIAddr = clashAddr
	}
	if len(hysteriaPorts) > 0 {
		c.hysteriaPorts = hysteriaPorts
	}
	if logPaths != nil {
		for k, v := range logPaths {
			c.logPaths[k] = v
		}
	}
}

// GetStatus returns the operational status of all core engines
func (c *Controller) GetStatus() map[string]CoreStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()

	status := make(map[string]CoreStatus)
	pm := GetProcessManager()

	// Check Sing-box
	sbRunning := pm.IsRunning("sing-box")
	if !sbRunning {
		if _, err := localHTTPClient.Get("http://" + c.clashAPIAddr + "/connections"); err == nil {
			sbRunning = true
		}
	}
	status["sing-box"] = CoreStatus{
		Name:    "sing-box",
		Running: sbRunning,
	}

	// Check Hysteria 2
	hyRunning := pm.IsRunning("hysteria2")
	if !hyRunning {
		for _, port := range c.hysteriaPorts {
			if _, err := localHTTPClient.Get(fmt.Sprintf("http://127.0.0.1:%d/traffic", port)); err == nil {
				hyRunning = true
				break
			}
		}
	}
	status["hysteria2"] = CoreStatus{
		Name:    "hysteria2",
		Running: hyRunning,
	}

	// Check Xray
	xrayRunning := pm.IsRunning("xray")
	status["xray"] = CoreStatus{
		Name:    "xray",
		Running: xrayRunning,
	}

	return status
}

// GetUnifiedTraffic collects and aggregates traffic from all active engines
func (c *Controller) GetUnifiedTraffic() (map[string]ClientTraffic, error) {
	c.mu.RLock()
	clashAddr := c.clashAPIAddr
	hyPorts := make([]int, len(c.hysteriaPorts))
	copy(hyPorts, c.hysteriaPorts)
	c.mu.RUnlock()

	aggregated := make(map[string]ClientTraffic)

	// 1. Sing-box
	if sbTraffic, err := FetchSingBoxTraffic(clashAddr); err == nil {
		for email, t := range sbTraffic {
			aggregated[email] = t
		}
	}

	// 2. Hysteria 2 (iterate all ports)
	for _, port := range hyPorts {
		if hyTraffic, err := FetchHysteriaTraffic(port); err == nil {
			for email, t := range hyTraffic {
				entry := aggregated[email]
				entry.Email = email
				entry.UpBytes += t.UpBytes
				entry.DownBytes += t.DownBytes
				entry.Connections += t.Connections
				if t.Online {
					entry.Online = true
				}
				aggregated[email] = entry
			}
		}
	}

	return aggregated, nil
}

// KickClient terminates sessions for a given client email across all cores
func (c *Controller) KickClient(email string) error {
	c.mu.RLock()
	clashAddr := c.clashAPIAddr
	hyPorts := make([]int, len(c.hysteriaPorts))
	copy(hyPorts, c.hysteriaPorts)
	c.mu.RUnlock()

	var wg sync.WaitGroup

	// 1. Kick from Sing-box (concurrent)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = CloseSingBoxConnections(clashAddr, email)
	}()

	// 2. Kick from Hysteria 2 instances (concurrent)
	for _, port := range hyPorts {
		p := port
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = KickHysteriaClient(p, email)
		}()
	}

	// 3. Kick from Xray-core (concurrent)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = KickXrayClient("127.0.0.1:10085", nil, email)
	}()

	wg.Wait()
	return nil
}

// GetLogs reads lines from in-memory buffer or log path of the specified core
func (c *Controller) GetLogs(coreName string, lines int) ([]string, error) {
	inMem := GetProcessManager().GetInMemoryLogs(coreName, lines)
	if len(inMem) > 0 {
		return inMem, nil
	}

	c.mu.RLock()
	path, ok := c.logPaths[coreName]
	c.mu.RUnlock()

	if !ok || path == "" {
		return []string{}, nil
	}

	return ReadCoreLogs(path, lines)
}
