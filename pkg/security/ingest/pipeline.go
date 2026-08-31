package ingest

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/security/detector"
	"github.com/blackalex1/sentinel-core/pkg/security/netfilter"
	"github.com/blackalex1/sentinel-core/pkg/security/ssh"
	"github.com/blackalex1/sentinel-core/pkg/supervisor"
)

// PipelineConfig holds configuration for the unified ingestion pipeline.
type PipelineConfig struct {
	VPNVMID              int      `json:"vpn_vmid"`
	VPNVMIDs             []int    `json:"vpn_vmids"`
	TrustedAdminIPs      []string `json:"trusted_admin_ips"`
	ProxmoxHost          string   `json:"proxmox_host"`
	SensitivePorts       []int    `json:"sensitive_ports"`
	WhitelistPorts       []int    `json:"whitelist_ports"`
	WhitelistVMIDs       []int    `json:"whitelist_vmids"`
	Language             string   `json:"language"`
	AutoBanScanners      bool     `json:"auto_ban_scanners"`
	ProxmoxLogPath       string   `json:"proxmox_log_path,omitempty"`
	AuthLogPath          string   `json:"auth_log_path,omitempty"`
	RouterConfig         *RouterSSHConfig `json:"router_config,omitempty"`
}

// SecurityPipeline runs high-speed ingestion and threat evaluation across all traffic sources.
type SecurityPipeline struct {
	mu            sync.RWMutex
	config        PipelineConfig
	policy        netfilter.ClassifierPolicy
	dispatcher    *EventDispatcher
	threatDetector *netfilter.RouterThreatDetector
	tailers       []*LogTailer
	routerWatcher *RouterSSHWatcher
	running       bool
	cancelFn      context.CancelFunc
}

var defaultPipeline = NewSecurityPipeline(DefaultPipelineConfig())

// GetDefaultSecurityPipeline returns the singleton pipeline instance.
func GetDefaultSecurityPipeline() *SecurityPipeline {
	return defaultPipeline
}

// DefaultPipelineConfig returns standard pipeline defaults.
func DefaultPipelineConfig() PipelineConfig {
	return PipelineConfig{
		VPNVMID:         100,
		VPNVMIDs:        []int{100},
		SensitivePorts:  []int{22, 23, 8006, 2222, 3389, 445, 135, 139, 1433, 5555},
		WhitelistPorts:  []int{80, 443, 53, 123},
		Language:        "ru",
		AutoBanScanners: true,
	}
}

// NewSecurityPipeline creates a new SecurityPipeline.
func NewSecurityPipeline(cfg PipelineConfig) *SecurityPipeline {
	policy := netfilter.DefaultClassifierPolicy()
	policy.VPNVMID = cfg.VPNVMID
	policy.VPNVMIDs = cfg.VPNVMIDs
	policy.TrustedAdminIPs = cfg.TrustedAdminIPs
	policy.ProxmoxHost = cfg.ProxmoxHost
	if len(cfg.SensitivePorts) > 0 {
		policy.SensitivePorts = cfg.SensitivePorts
	}
	if len(cfg.WhitelistPorts) > 0 {
		policy.WhitelistPorts = cfg.WhitelistPorts
	}
	policy.LXCWhitelistVMIDs = cfg.WhitelistVMIDs

	return &SecurityPipeline{
		config:         cfg,
		policy:         policy,
		dispatcher:     GetDefaultEventDispatcher(),
		threatDetector: netfilter.GetDefaultRouterThreatDetector(),
		tailers:        make([]*LogTailer, 0),
	}
}

// Configure updates the pipeline policy and settings at runtime.
func (p *SecurityPipeline) Configure(cfg PipelineConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = cfg

	policy := netfilter.DefaultClassifierPolicy()
	policy.VPNVMID = cfg.VPNVMID
	policy.VPNVMIDs = cfg.VPNVMIDs
	policy.TrustedAdminIPs = cfg.TrustedAdminIPs
	policy.ProxmoxHost = cfg.ProxmoxHost
	if len(cfg.SensitivePorts) > 0 {
		policy.SensitivePorts = cfg.SensitivePorts
	}
	if len(cfg.WhitelistPorts) > 0 {
		policy.WhitelistPorts = cfg.WhitelistPorts
	}
	policy.LXCWhitelistVMIDs = cfg.WhitelistVMIDs
	p.policy = policy
}

// ProcessProxmoxIptablesLine ingests and classifies a raw kernel iptables line.
func (p *SecurityPipeline) ProcessProxmoxIptablesLine(line string) *SecurityEvent {
	if line == "" || !strings.Contains(line, "PROTO=") {
		return nil
	}

	ev := netfilter.ParseIptablesLine(line, p.config.VPNVMID)
	if ev == nil {
		return nil
	}

	// Classify connection
	res := netfilter.ClassifyConnection(*ev, p.policy, p.config.Language)

	// Filter INFO level to minimize noise unless it's a critical VPN client session
	if res.RiskLevel == netfilter.LevelInfo {
		return nil
	}

	// Try in-memory VPN client attribution
	var clientEmail string
	var realClientIP string
	if ev.VMID == p.config.VPNVMID || containsInt(p.config.VPNVMIDs, ev.VMID) {
		clientEmail = supervisor.GetSessionTracker().FindClientByIP(ev.Src)
		if clientEmail == "" {
			realClientIP = netfilter.FindRealVPNClientIP(ev.Proto, ev.Src, ev.Dst, ev.SPT, ev.DPT, "")
			if realClientIP != "" {
				clientEmail = supervisor.GetSessionTracker().FindClientByIP(realClientIP)
			}
		}
	}

	secEvent := SecurityEvent{
		EventID:       fmt.Sprintf("prox-%d", time.Now().UnixNano()),
		EventType:     "THREAT_DETECTED",
		Source:        "proxmox_iptables",
		Timestamp:     time.Now(),
		RiskLevel:     string(res.RiskLevel),
		SrcIP:         ev.Src,
		SrcPort:       ev.SPT,
		DstHost:       ev.Dst,
		DstPort:       ev.DPT,
		Proto:         ev.Proto,
		VMID:          ev.VMID,
		Direction:     ev.Direction,
		Reason:        res.Description,
		ThreatType:    res.Label,
		ClientEmail:   clientEmail,
		RealClientIP:  realClientIP,
		RawLine:       line,
	}

	p.dispatcher.Emit(secEvent)
	return &secEvent
}

// ProcessRouterConntrackLine ingests a router conntrack line.
func (p *SecurityPipeline) ProcessRouterConntrackLine(line string) *SecurityEvent {
	if !strings.Contains(line, "[NEW]") {
		return nil
	}

	routerEv := netfilter.ParseRouterConntrackLine(line)
	if routerEv == nil || !routerEv.IsThreat {
		return nil
	}

	eventType := "THREAT_DETECTED"
	if routerEv.ShouldAutoBan {
		eventType = "ROUTER_AUTOBLOCK"
	}

	secEvent := SecurityEvent{
		EventID:       fmt.Sprintf("rct-%d", time.Now().UnixNano()),
		EventType:     eventType,
		Source:        "router_conntrack",
		Timestamp:     time.Now(),
		RiskLevel:     "WARNING",
		SrcIP:         routerEv.SrcIP,
		SrcPort:       routerEv.SrcPort,
		DstHost:       routerEv.DstHost,
		DstPort:       routerEv.DstPort,
		Proto:         routerEv.Proto,
		Reason:        routerEv.Reason,
		ThreatType:    routerEv.ThreatType,
		ShouldAutoBan: routerEv.ShouldAutoBan,
		RawLine:       line,
	}
	if routerEv.ShouldAutoBan {
		secEvent.RiskLevel = "CRITICAL"
	}

	p.dispatcher.Emit(secEvent)
	return &secEvent
}

// ProcessRouterIptablesLine ingests a router syslog line.
func (p *SecurityPipeline) ProcessRouterIptablesLine(line string) *SecurityEvent {
	if !strings.Contains(line, "ROUTER-IPS:") {
		return nil
	}

	routerEv := netfilter.ParseRouterIptablesLine(line)
	if routerEv == nil || !routerEv.IsThreat {
		return nil
	}

	eventType := "THREAT_DETECTED"
	if routerEv.ShouldAutoBan {
		eventType = "ROUTER_AUTOBLOCK"
	}

	secEvent := SecurityEvent{
		EventID:       fmt.Sprintf("ript-%d", time.Now().UnixNano()),
		EventType:     eventType,
		Source:        "router_syslog",
		Timestamp:     time.Now(),
		RiskLevel:     "WARNING",
		SrcIP:         routerEv.SrcIP,
		SrcPort:       routerEv.SrcPort,
		DstHost:       routerEv.DstHost,
		DstPort:       routerEv.DstPort,
		Proto:         routerEv.Proto,
		Reason:        routerEv.Reason,
		ThreatType:    routerEv.ThreatType,
		ShouldAutoBan: routerEv.ShouldAutoBan,
		RawLine:       line,
	}
	if routerEv.ShouldAutoBan {
		secEvent.RiskLevel = "CRITICAL"
	}

	p.dispatcher.Emit(secEvent)
	return &secEvent
}

// ProcessAuthLogLine ingests an SSH auth.log line for brute-force tracking.
func (p *SecurityPipeline) ProcessAuthLogLine(line string) *SecurityEvent {
	authEv, ok := ssh.ParseAuthLine(line)
	if !ok || authEv == nil {
		return nil
	}

	risk := "INFO"
	if authEv.Type == ssh.EventSSHFailedAuth || authEv.Type == ssh.EventPVEWebFail {
		risk = "WARNING"
	}

	secEvent := SecurityEvent{
		EventID:     fmt.Sprintf("auth-%d", time.Now().UnixNano()),
		EventType:   "AUTH_EVENT",
		Source:      "auth_ssh",
		Timestamp:   time.Now(),
		RiskLevel:   risk,
		SrcIP:       authEv.SourceIP,
		SrcPort:     authEv.Port,
		DstPort:     22,
		Proto:       "TCP",
		Reason:      fmt.Sprintf("SSH %s for user %s from %s", authEv.Type, authEv.User, authEv.SourceIP),
		ThreatType:  string(authEv.Type),
		RawLine:     line,
	}

	if risk == "WARNING" {
		p.dispatcher.Emit(secEvent)
	}
	return &secEvent
}

// ProcessProxyCoreLine processes live log output from Sing-box, Xray, or Hysteria 2.
func (p *SecurityPipeline) ProcessProxyCoreLine(coreName, line string) {
	if line == "" {
		return
	}
	// Push to supervisor in-memory broadcaster and session tracker
	supervisor.GetLogBroadcaster().PushLine(coreName, line)

	// Audit with log detector
	event, ok := detector.ParseCoreLogLine(coreName, line)
	if !ok || event == nil {
		return
	}

	if event.EventType == "SSRF_PROBE" || event.EventType == "AUTH_FAIL" {
		secEvent := SecurityEvent{
			EventID:     fmt.Sprintf("core-%d", time.Now().UnixNano()),
			EventType:   "THREAT_DETECTED",
			Source:      "proxy_core",
			Timestamp:   time.Now(),
			RiskLevel:   "CRITICAL",
			SrcIP:       event.ClientIP,
			DstHost:     event.TargetHost,
			DstPort:     event.TargetPort,
			Reason:      fmt.Sprintf("[%s] %s probe to %s:%d", coreName, event.EventType, event.TargetHost, event.TargetPort),
			ThreatType:  event.EventType,
			ClientEmail: event.ClientRawID,
			RawLine:     line,
		}
		p.dispatcher.Emit(secEvent)
	}
}

// Start begins all background tailers and streamers.
func (p *SecurityPipeline) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return nil
	}
	p.running = true
	subCtx, cancel := context.WithCancel(ctx)
	p.cancelFn = cancel

	// 1. Proxmox traffic tailer
	if p.config.ProxmoxLogPath != "" {
		tailer := NewFileTailer(p.config.ProxmoxLogPath, func(line string) {
			p.ProcessProxmoxIptablesLine(line)
		})
		p.tailers = append(p.tailers, tailer)
		_ = tailer.Start(subCtx)
	}

	// 2. Auth log tailer
	if p.config.AuthLogPath != "" {
		authTailer := NewFileTailer(p.config.AuthLogPath, func(line string) {
			p.ProcessAuthLogLine(line)
		})
		p.tailers = append(p.tailers, authTailer)
		_ = authTailer.Start(subCtx)
	}

	// 3. Router SSH watcher
	if p.config.RouterConfig != nil && p.config.RouterConfig.Host != "" {
		p.routerWatcher = NewRouterSSHWatcher(*p.config.RouterConfig, func(line string) {
			if strings.Contains(line, "[NEW]") {
				p.ProcessRouterConntrackLine(line)
			} else if strings.Contains(line, "ROUTER-IPS:") {
				p.ProcessRouterIptablesLine(line)
			}
		})
		_ = p.routerWatcher.Start(subCtx)
	}

	return nil
}

// Stop terminates all background tailers.
func (p *SecurityPipeline) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cancelFn != nil {
		p.cancelFn()
	}
	for _, t := range p.tailers {
		t.Stop()
	}
	if p.routerWatcher != nil {
		p.routerWatcher.Stop()
	}
	p.running = false
}

func containsInt(slice []int, val int) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
