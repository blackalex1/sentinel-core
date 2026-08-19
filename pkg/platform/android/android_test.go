package android

import (
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func TestAndroidTunSpec_Defaults(t *testing.T) {
	spec := DefaultTunSpec()
	if spec.Mode != ast.InboundModeMobileVpn {
		t.Errorf("expected InboundModeMobileVpn, got %s", spec.Mode)
	}
	if spec.TunInterfaceName != "tun0" {
		t.Errorf("expected tun0, got %s", spec.TunInterfaceName)
	}
	if spec.TunStack != "gvisor" {
		t.Errorf("expected gvisor, got %s", spec.TunStack)
	}
	if spec.MTU != 1500 {
		t.Errorf("expected MTU 1500, got %d", spec.MTU)
	}
}

func TestBuildXrayAndroidTunInbound(t *testing.T) {
	spec := DefaultTunSpec()
	inbound := BuildXrayAndroidTunInbound(&spec)
	if inbound == nil {
		t.Fatalf("expected non-nil xray tun inbound")
	}
	if inbound["protocol"] != "tun" {
		t.Errorf("expected protocol tun, got %v", inbound["protocol"])
	}
	if inbound["tag"] != "tun-in" {
		t.Errorf("expected tag tun-in, got %v", inbound["tag"])
	}

	settings, ok := inbound["settings"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected settings map")
	}
	if settings["name"] != "tun0" {
		t.Errorf("expected tun0, got %v", settings["name"])
	}
	if settings["stack"] != "gvisor" {
		t.Errorf("expected gvisor, got %v", settings["stack"])
	}
}

func TestBuildSingBoxAndroidTunInbound(t *testing.T) {
	spec := DefaultTunSpec()
	inbound := BuildSingBoxAndroidTunInbound(&spec)
	if inbound == nil {
		t.Fatalf("expected non-nil singbox tun inbound")
	}
	if inbound["type"] != "tun" {
		t.Errorf("expected type tun, got %v", inbound["type"])
	}
	if inbound["tag"] != "tun-in" {
		t.Errorf("expected tag tun-in, got %v", inbound["tag"])
	}
}

func TestAndroidInbound_LanSharingSpec(t *testing.T) {
	spec := DefaultTunSpec()
	spec.LanSharingEnabled = true
	spec.LanHTTPPort = 10809
	spec.LanSocksPort = 10808
	spec.LanAuthEnabled = true
	spec.LanUsername = "admin"
	spec.LanPassword = "secretpassword"

	if !spec.LanSharingEnabled {
		t.Errorf("expected LanSharingEnabled true")
	}
	if spec.LanHTTPPort != 10809 || spec.LanSocksPort != 10808 {
		t.Errorf("unexpected ports")
	}
	if !spec.LanAuthEnabled || spec.LanUsername != "admin" {
		t.Errorf("unexpected auth settings")
	}
}

