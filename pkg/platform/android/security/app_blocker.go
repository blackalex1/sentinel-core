package security

import (
	"sync"
)

// AppBlockerManager manages per-package app blocking state on Android.
type AppBlockerManager struct {
	mu                  sync.RWMutex
	blockedApps         map[string]bool
	flaggedSystemApps   map[string]bool
	blockedDestinations map[string]bool
	blockedPorts        map[int]bool
}

var (
	defaultAppBlocker *AppBlockerManager
	appBlockerOnce    sync.Once
)

// GetDefaultEngine returns the global singleton app blocker for Android.
func GetDefaultEngine() *AppBlockerManager {
	appBlockerOnce.Do(func() {
		defaultAppBlocker = &AppBlockerManager{
			blockedApps:         make(map[string]bool),
			flaggedSystemApps:   make(map[string]bool),
			blockedDestinations: make(map[string]bool),
			blockedPorts:        make(map[int]bool),
		}
	})
	return defaultAppBlocker
}

// BlockApp manually blackholes a package.
func (e *AppBlockerManager) BlockApp(packageName string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.blockedApps[packageName] = true
}

// UnblockApp unblocks a package and resets its state.
func (e *AppBlockerManager) UnblockApp(packageName string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.blockedApps, packageName)
	delete(e.flaggedSystemApps, packageName)
}

// IsAppBlocked checks if package is currently blocked.
func (e *AppBlockerManager) IsAppBlocked(packageName string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.blockedApps[packageName]
}

// GetBlockedApps returns list of all blocked application packages.
func (e *AppBlockerManager) GetBlockedApps() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	apps := make([]string, 0, len(e.blockedApps))
	for app := range e.blockedApps {
		apps = append(apps, app)
	}
	return apps
}

// GetBlockedDestinations returns active destination IP blocks.
func (e *AppBlockerManager) GetBlockedDestinations() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	dests := make([]string, 0, len(e.blockedDestinations))
	for d := range e.blockedDestinations {
		dests = append(dests, d)
	}
	return dests
}

// GetBlockedPorts returns active port blocks.
func (e *AppBlockerManager) GetBlockedPorts() []int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ports := make([]int, 0, len(e.blockedPorts))
	for p := range e.blockedPorts {
		ports = append(ports, p)
	}
	return ports
}

// ClearAll resets all blocked apps.
func (e *AppBlockerManager) ClearAll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.blockedApps = make(map[string]bool)
	e.flaggedSystemApps = make(map[string]bool)
	e.blockedDestinations = make(map[string]bool)
	e.blockedPorts = make(map[int]bool)
}
