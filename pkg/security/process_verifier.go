package security

import (
	"fmt"
	"path/filepath"
	"strings"
)

// IsMasqueradedSystemProcess detects MITRE ATT&CK T1036 (Masquerading / Fake System Executables).
func IsMasqueradedSystemProcess(callerID, fullPath string) (bool, string) {
	name := strings.ToLower(filepath.Base(strings.ReplaceAll(callerID, "\\", "/")))
	path := strings.ToLower(strings.ReplaceAll(fullPath, "\\", "/"))

	systemBinaries := map[string]string{
		"svchost.exe":   "system32",
		"csrss.exe":     "system32",
		"lsass.exe":     "system32",
		"services.exe":  "system32",
		"smss.exe":      "system32",
		"taskhostw.exe": "system32",
		"dwm.exe":       "system32",
		"conhost.exe":   "system32",
		"explorer.exe":  "windows",
	}

	expectedSubdir, isSysBin := systemBinaries[name]
	if !isSysBin || path == "" {
		return false, ""
	}

	// Genuine system paths must be within /windows/system32 or /windows/syswow64
	if expectedSubdir == "system32" {
		if strings.Contains(path, "/windows/system32") || strings.Contains(path, "/windows/syswow64") {
			return false, ""
		}
	} else if expectedSubdir == "windows" {
		if strings.Contains(path, "/windows") && !strings.Contains(path, "/users/") && !strings.Contains(path, "/temp/") && !strings.Contains(path, "/appdata/") {
			return false, ""
		}
	}

	return true, fmt.Sprintf("MITRE T1036: Маскировка процесса! Вредоносный бинарник '%s' запущен вне системной директории Windows (%s)", name, fullPath)
}

// isProtectedSystemEntity ensures ONLY genuinely verified OS components are immune to broad quarantine.
func isProtectedSystemEntity(caller, execPath string) bool {
	clean := strings.ToLower(strings.TrimSpace(caller))
	p := strings.ToLower(strings.ReplaceAll(execPath, "\\", "/"))

	if clean == "android" || clean == "android.system.kernel" ||
		strings.HasPrefix(clean, "android.system.") ||
		strings.HasPrefix(clean, "android.uid.") ||
		strings.HasPrefix(clean, "unknown.uid.") {
		return true
	}

	switch clean {
	case "", "defaultentity", "unknown", "pending", "127.0.0.1", "::1":
		return true
	case "system", "system.exe", "kernel", "ntoskrnl.exe":
		return p == "" || !strings.Contains(p, "/users/")
	case "svchost.exe", "csrss.exe", "lsass.exe", "services.exe", "smss.exe", "taskhostw.exe", "dwm.exe", "conhost.exe":
		return p == "" || strings.Contains(p, "/windows/system32") || strings.Contains(p, "/windows/syswow64")
	case "explorer.exe":
		return p == "" || (strings.Contains(p, "/windows") && !strings.Contains(p, "/users/") && !strings.Contains(p, "/temp/") && !strings.Contains(p, "/appdata/"))
	default:
		return false
	}
}
