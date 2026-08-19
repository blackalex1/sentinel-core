package desktop

import (
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func TestDesktopTunSpec_Defaults(t *testing.T) {
	spec := DefaultDesktopTunSpec()
	if spec.Mode != ast.InboundModeDesktopTun {
		t.Errorf("expected InboundModeDesktopTun, got %s", spec.Mode)
	}
	if spec.TunInterfaceName != "sentinel-tun" {
		t.Errorf("expected sentinel-tun, got %s", spec.TunInterfaceName)
	}
	if spec.TunStack != "mixed" {
		t.Errorf("expected mixed, got %s", spec.TunStack)
	}
	if spec.MTU != 9000 {
		t.Errorf("expected MTU 9000, got %d", spec.MTU)
	}
}

func TestBuildXrayDesktopTunInbound(t *testing.T) {
	spec := DefaultDesktopTunSpec()
	inbound := BuildXrayDesktopTunInbound(&spec)
	if inbound == nil {
		t.Fatalf("expected non-nil xray desktop tun inbound")
	}
	if inbound["protocol"] != "tun" {
		t.Errorf("expected protocol tun, got %v", inbound["protocol"])
	}
	if inbound["tag"] != "tun-in" {
		t.Errorf("expected tag tun-in, got %v", inbound["tag"])
	}
}

func TestBuildSingBoxDesktopTunInbound(t *testing.T) {
	spec := DefaultDesktopTunSpec()
	inbound := BuildSingBoxDesktopTunInbound(&spec)
	if inbound == nil {
		t.Fatalf("expected non-nil singbox desktop tun inbound")
	}
	if inbound["type"] != "tun" {
		t.Errorf("expected type tun, got %v", inbound["type"])
	}
	if inbound["tag"] != "tun-in" {
		t.Errorf("expected tag tun-in, got %v", inbound["tag"])
	}
}
