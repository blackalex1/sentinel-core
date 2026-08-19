package security

import (
	"strings"
	"sync"
	"time"
)

// ActionVerdict represents the decision made by the threat engine.
type ActionVerdict string

const (
	ActionAllow      ActionVerdict = "ALLOW"
	ActionBlock      ActionVerdict = "BLOCK"
	ActionFlagSystem ActionVerdict = "FLAG_SYSTEM"
)

// ThreatType defines the detected anomalous behavior.
type ThreatType string

const (
	ThreatNone          ThreatType = "NONE"
	ThreatHighFrequency ThreatType = "HIGH_FREQUENCY_PROBE"
	ThreatPortScan      ThreatType = "PORT_SCAN"
	ThreatSensitivePort ThreatType = "SENSITIVE_PORT_PROBE"
	ThreatMalwareC2     ThreatType = "MALWARE_C2_SUSPECT"
	ThreatFlood         ThreatType = "FLOOD_BURST"
)

// ConnectionRecord represents a single connection packet or socket event.
type ConnectionRecord struct {
	Timestamp     time.Time `json:"timestamp"`
	DestinationIP string    `json:"destination_ip"`
	Port          int       `json:"port"`
	Protocol      string    `json:"protocol"`
	IPLength      int       `json:"ip_length"`
	TTL           int       `json:"ttl"`
	IPFlags       string    `json:"ip_flags"`
	TCPFlags      string    `json:"tcp_flags"`
	TCPSeq        uint32    `json:"tcp_seq"`
	TCPAck        uint32    `json:"tcp_ack"`
	TCPWindow     int       `json:"tcp_window"`
	RawBytes      []byte    `json:"raw_bytes,omitempty"`
}

// AppRiskRating tracks the risk score and violation history of an Android package.
type AppRiskRating struct {
	PackageName     string             `json:"package_name"`
	AppName         string             `json:"app_name"`
	RiskScore       int                `json:"risk_score"`
	LastDecayTime   time.Time          `json:"last_decay_time"`
	FirstSeen       time.Time          `json:"first_seen"`
	LastViolation   time.Time          `json:"last_violation"`
	TriggerTime     time.Time          `json:"trigger_time"`
	ProbedPorts     map[int]time.Time  `json:"probed_ports"`
	RecentAttempts  []ConnectionRecord `json:"recent_attempts"`
	ThreatCount     int                `json:"threat_count"`
	IsSystem        bool               `json:"is_system"`
}

// AuditRequest contains the connection parameters sent from the Android interceptor.
type AuditRequest struct {
	PackageName   string   `json:"package_name"`
	AppName       string   `json:"app_name"`
	DestinationIP string   `json:"destination_ip"`
	Port          int      `json:"port"`
	Protocol      string   `json:"protocol"`
	IPLength      int      `json:"ip_length"`
	TTL           int      `json:"ttl"`
	IPFlags       string   `json:"ip_flags"`
	TCPFlags      string   `json:"tcp_flags"`
	TCPSeq        uint32   `json:"tcp_seq"`
	TCPAck        uint32   `json:"tcp_ack"`
	TCPWindow     int      `json:"tcp_window"`
	RawBytes      []byte   `json:"raw_bytes,omitempty"`
	AuditPorts    []int    `json:"audit_ports,omitempty"`    // Dynamic ports from app settings
	MaxThreshold  int      `json:"max_threshold,omitempty"`  // Default: 2 requests / min for non-web
}

// AuditVerdict details the security analysis result.
type AuditVerdict struct {
	IsBlocked       bool          `json:"is_blocked"`
	ShouldBlock     bool          `json:"should_block"`
	IsSystemFlagged bool          `json:"is_system_flagged"`
	ThreatDetected  bool          `json:"threat_detected"`
	ThreatType      ThreatType    `json:"threat_type"`
	Description     string        `json:"description"`
	Action          ActionVerdict `json:"action"`
	RiskScore       int           `json:"risk_score"`
	AttemptsCount   int           `json:"attempts_count"`
	RecentAttempts  []ConnectionRecord `json:"recent_attempts,omitempty"`
	Timestamp       int64         `json:"timestamp"`
}

// AndroidThreatEngine is the high-performance Go traffic analytics & threat detector.
type AndroidThreatEngine struct {
	mu                  sync.RWMutex
	ratings             map[string]*AppRiskRating
	blockedApps         map[string]bool
	flaggedSystemApps   map[string]bool
	blockedDestinations map[string]bool
	blockedPorts        map[int]bool
	decayDuration       time.Duration
	stopTicker          chan struct{}
}

var (
	defaultEngine *AndroidThreatEngine
	engineOnce    sync.Once
)

// GetDefaultEngine returns the global singleton threat engine for Android.
func GetDefaultEngine() *AndroidThreatEngine {
	engineOnce.Do(func() {
		defaultEngine = NewAndroidThreatEngine(5 * time.Minute)
	})
	return defaultEngine
}

// NewAndroidThreatEngine initializes a new threat detector with auto-decay interval.
func NewAndroidThreatEngine(decayInterval time.Duration) *AndroidThreatEngine {
	if decayInterval <= 0 {
		decayInterval = 5 * time.Minute
	}

	engine := &AndroidThreatEngine{
		ratings:             make(map[string]*AppRiskRating),
		blockedApps:         make(map[string]bool),
		flaggedSystemApps:   make(map[string]bool),
		blockedDestinations: make(map[string]bool),
		blockedPorts:        make(map[int]bool),
		decayDuration:       decayInterval,
		stopTicker:          make(chan struct{}),
	}

	go engine.startDecayWorker(decayInterval)

	return engine
}

// Close terminates background ticker routines.
func (e *AndroidThreatEngine) Close() {
	select {
	case <-e.stopTicker:
	default:
		close(e.stopTicker)
	}
}

// startDecayWorker resets and decays application risk scores every 5 minutes.
func (e *AndroidThreatEngine) startDecayWorker(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.ResetOrDecayScores()
		case <-e.stopTicker:
			return
		}
	}
}

// ResetOrDecayScores resets expired connection attempts and decays risk rating scores.
func (e *AndroidThreatEngine) ResetOrDecayScores() {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	for pkg, rating := range e.ratings {
		if rating == nil {
			continue
		}
		// Reset/decay rating score every 5 minutes
		if now.Sub(rating.LastDecayTime) >= e.decayDuration {
			rating.RiskScore = rating.RiskScore / 2
			if rating.RiskScore < 5 {
				rating.RiskScore = 0
			}
			rating.LastDecayTime = now
			rating.ProbedPorts = make(map[int]time.Time)
		}

		// Prune attempts older than 1 minute
		var valid []ConnectionRecord
		for _, attempt := range rating.RecentAttempts {
			if now.Sub(attempt.Timestamp) < 1*time.Minute {
				valid = append(valid, attempt)
			}
		}
		rating.RecentAttempts = valid

		// Clean empty unblocked clean records
		if rating.RiskScore == 0 && len(rating.RecentAttempts) == 0 && !e.blockedApps[pkg] && !e.flaggedSystemApps[pkg] {
			delete(e.ratings, pkg)
		}
	}
}

// IsSystemPackage determines if a package belongs to Android OS core services.
func IsSystemPackage(packageName string) bool {
	if packageName == "android" ||
		packageName == "android.system.kernel" ||
		strings.HasPrefix(packageName, "android.system.") ||
		strings.HasPrefix(packageName, "android.uid.") ||
		strings.HasPrefix(packageName, "unknown.uid.") {
		return true
	}
	return false
}

// IsStandardDNSOrWeb checks if destination is standard public web/DNS traffic.
func IsStandardDNSOrWeb(destinationIP string, port int) bool {
	if port == 53 || port == 80 || port == 443 || port == 853 {
		return true
	}
	if destinationIP == "8.8.8.8" || destinationIP == "8.8.4.4" ||
		destinationIP == "1.1.1.1" || destinationIP == "1.0.0.1" ||
		destinationIP == "127.0.0.1" || destinationIP == "localhost" ||
		strings.HasPrefix(destinationIP, "2001:4860:") ||
		strings.HasPrefix(destinationIP, "2606:4700:") {
		return true
	}
	return false
}

// AuditConnection processes an incoming socket event, updates risk rating, and returns the verdict.
func (e *AndroidThreatEngine) AuditConnection(req AuditRequest) AuditVerdict {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	nowMs := now.UnixMilli()

	// 1. Check if the app is already actively blackholed
	if e.blockedApps[req.PackageName] {
		if !IsStandardDNSOrWeb(req.DestinationIP, req.Port) {
			e.blockedDestinations[req.DestinationIP] = true
			e.blockedPorts[req.Port] = true
		}
		return AuditVerdict{
			IsBlocked:      true,
			ShouldBlock:    true,
			ThreatDetected: true,
			ThreatType:     ThreatMalwareC2,
			Description:    "Application is actively quarantined",
			Action:         ActionBlock,
			RiskScore:      100,
			Timestamp:      nowMs,
		}
	}

	// 2. Dynamic Audit Ports Check (if configured by user settings)
	if len(req.AuditPorts) > 0 {
		portMatched := false
		for _, p := range req.AuditPorts {
			if p == req.Port {
				portMatched = true
				break
			}
		}
		if !portMatched {
			return AuditVerdict{
				IsBlocked: false,
				Action:    ActionAllow,
				Timestamp: nowMs,
			}
		}
	}

	// 3. Retrieve or create app rating record
	rating, exists := e.ratings[req.PackageName]
	if !exists {
		rating = &AppRiskRating{
			PackageName:    req.PackageName,
			AppName:        req.AppName,
			RiskScore:      0,
			LastDecayTime:  now,
			FirstSeen:      now,
			ProbedPorts:    make(map[int]time.Time),
			RecentAttempts: make([]ConnectionRecord, 0, 10),
			IsSystem:       IsSystemPackage(req.PackageName),
		}
		e.ratings[req.PackageName] = rating
	}

	// Prune attempts older than 1 minute
	var recent []ConnectionRecord
	for _, a := range rating.RecentAttempts {
		if now.Sub(a.Timestamp) < 1*time.Minute {
			recent = append(recent, a)
		}
	}

	currentRecord := ConnectionRecord{
		Timestamp:     now,
		DestinationIP: req.DestinationIP,
		Port:          req.Port,
		Protocol:      req.Protocol,
		IPLength:      req.IPLength,
		TTL:           req.TTL,
		IPFlags:       req.IPFlags,
		TCPFlags:      req.TCPFlags,
		TCPSeq:        req.TCPSeq,
		TCPAck:        req.TCPAck,
		TCPWindow:     req.TCPWindow,
		RawBytes:      req.RawBytes,
	}
	recent = append(recent, currentRecord)
	rating.RecentAttempts = recent
	rating.ProbedPorts[req.Port] = now

	// 4. Threshold & Threat Analysis
	threshold := req.MaxThreshold
	if threshold <= 0 {
		threshold = 2 // Default: Max 2 non-web attempts per minute
	}

	isWeb := IsStandardDNSOrWeb(req.DestinationIP, req.Port)
	threatDetected := false
	threatType := ThreatNone
	desc := ""

	// Check Port Scanning (More than 4 distinct non-standard ports within window)
	if len(rating.ProbedPorts) >= 4 && !isWeb {
		threatDetected = true
		threatType = ThreatPortScan
		desc = "Port scanning detected across multiple ports"
		rating.RiskScore += 50
	} else if len(recent) > threshold && !isWeb {
		threatDetected = true
		threatType = ThreatHighFrequency
		desc = "High-frequency connection burst to non-standard port"
		rating.RiskScore += 35
	}

	if rating.RiskScore > 100 {
		rating.RiskScore = 100
	}

	if threatDetected {
		rating.LastViolation = now
		rating.ThreatCount++
		rating.TriggerTime = now

		// Handle System Package Protection
		if rating.IsSystem {
			e.flaggedSystemApps[req.PackageName] = true
			return AuditVerdict{
				IsBlocked:       false,
				ShouldBlock:     false,
				IsSystemFlagged: true,
				ThreatDetected:  true,
				ThreatType:      threatType,
				Description:     desc,
				Action:          ActionFlagSystem,
				RiskScore:       rating.RiskScore,
				AttemptsCount:   len(recent),
				RecentAttempts:  recent,
				Timestamp:       nowMs,
			}
		}

		// Block User Application
		e.blockedApps[req.PackageName] = true
		if !isWeb {
			e.blockedDestinations[req.DestinationIP] = true
			e.blockedPorts[req.Port] = true
		}

		return AuditVerdict{
			IsBlocked:      true,
			ShouldBlock:    true,
			ThreatDetected: true,
			ThreatType:     threatType,
			Description:    desc,
			Action:         ActionBlock,
			RiskScore:      rating.RiskScore,
			AttemptsCount:  len(recent),
			RecentAttempts: recent,
			Timestamp:      nowMs,
		}
	}

	return AuditVerdict{
		IsBlocked:      false,
		ShouldBlock:    false,
		ThreatDetected: false,
		ThreatType:     ThreatNone,
		Action:         ActionAllow,
		RiskScore:      rating.RiskScore,
		AttemptsCount:  len(recent),
		Timestamp:      nowMs,
	}
}

// BlockApp manually blackholes a package.
func (e *AndroidThreatEngine) BlockApp(packageName string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.blockedApps[packageName] = true
}

// UnblockApp unblocks a package and resets its counters.
func (e *AndroidThreatEngine) UnblockApp(packageName string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.blockedApps, packageName)
	delete(e.flaggedSystemApps, packageName)
	delete(e.ratings, packageName)
}

// IsAppBlocked checks if package is currently blocked.
func (e *AndroidThreatEngine) IsAppBlocked(packageName string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.blockedApps[packageName]
}

// GetBlockedApps returns list of all blocked application packages.
func (e *AndroidThreatEngine) GetBlockedApps() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	apps := make([]string, 0, len(e.blockedApps))
	for app := range e.blockedApps {
		apps = append(apps, app)
	}
	return apps
}

// GetBlockedDestinations returns active destination IP blocks.
func (e *AndroidThreatEngine) GetBlockedDestinations() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	dests := make([]string, 0, len(e.blockedDestinations))
	for d := range e.blockedDestinations {
		dests = append(dests, d)
	}
	return dests
}

// GetBlockedPorts returns active port blocks.
func (e *AndroidThreatEngine) GetBlockedPorts() []int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ports := make([]int, 0, len(e.blockedPorts))
	for p := range e.blockedPorts {
		ports = append(ports, p)
	}
	return ports
}

// ClearAll resets all blocked apps and ratings.
func (e *AndroidThreatEngine) ClearAll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ratings = make(map[string]*AppRiskRating)
	e.blockedApps = make(map[string]bool)
	e.flaggedSystemApps = make(map[string]bool)
	e.blockedDestinations = make(map[string]bool)
	e.blockedPorts = make(map[int]bool)
}
