package security

import (
	"testing"
)

func TestProcessVerifier_IsMasqueradedSystemProcess(t *testing.T) {
	cases := []struct {
		name        string
		callerID    string
		fullPath    string
		expectMasq  bool
	}{
		{"Genuine svchost in System32", "svchost.exe", `C:\Windows\System32\svchost.exe`, false},
		{"Genuine svchost in SysWOW64", "svchost.exe", `C:\Windows\SysWOW64\svchost.exe`, false},
		{"Fake svchost in Users temp", "svchost.exe", `C:\Users\User\AppData\Local\Temp\svchost.exe`, true},
		{"Fake svchost in Downloads", "svchost.exe", `C:\Users\Admin\Downloads\svchost.exe`, true},
		{"Genuine explorer in Windows", "explorer.exe", `C:\Windows\explorer.exe`, false},
		{"Fake explorer in AppData", "explorer.exe", `C:\Users\User\AppData\Roaming\explorer.exe`, true},
		{"Fake explorer in Temp", "explorer.exe", `C:\Temp\explorer.exe`, true},
		{"Normal non-system binary", "chrome.exe", `C:\Program Files\Google\Chrome\Application\chrome.exe`, false},
		{"Empty path for system binary", "svchost.exe", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isMasq, reason := IsMasqueradedSystemProcess(tc.callerID, tc.fullPath)
			if isMasq != tc.expectMasq {
				t.Errorf("IsMasqueradedSystemProcess(%s, %s) = %v; want %v (reason: %s)", tc.callerID, tc.fullPath, isMasq, tc.expectMasq, reason)
			}
		})
	}
}

func TestProcessVerifier_IsProtectedSystemEntity(t *testing.T) {
	cases := []struct {
		name       string
		caller     string
		execPath   string
		expected   bool
	}{
		{"Android root entity", "android", "", true},
		{"Android kernel", "android.system.kernel", "", true},
		{"Android system package", "android.system.service", "", true},
		{"Android UID", "android.uid.system:1000", "", true},
		{"Unknown UID", "unknown.uid.10052", "", true},
		{"Empty caller", "", "", true},
		{"DefaultEntity", "DefaultEntity", "", true},
		{"Pending caller", "pending", "", true},
		{"Localhost caller", "127.0.0.1", "", true},
		{"Localhost IPv6", "::1", "", true},
		{"Genuine system kernel", "system", `C:\Windows\System32\ntoskrnl.exe`, true},
		{"Spoofed system in users", "system", `C:\Users\Malware\system.exe`, false},
		{"Genuine svchost", "svchost.exe", `C:\Windows\System32\svchost.exe`, true},
		{"Spoofed svchost", "svchost.exe", `C:\ProgramData\svchost.exe`, false},
		{"Genuine explorer", "explorer.exe", `C:\Windows\explorer.exe`, true},
		{"Spoofed explorer", "explorer.exe", `C:\Users\User\AppData\Local\explorer.exe`, false},
		{"Third party app", "my_app.exe", `C:\Program Files\App\my_app.exe`, false},
		{"Malware", "rat.exe", `C:\Temp\rat.exe`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := isProtectedSystemEntity(tc.caller, tc.execPath)
			if res != tc.expected {
				t.Errorf("isProtectedSystemEntity(%s, %s) = %v; want %v", tc.caller, tc.execPath, res, tc.expected)
			}
		})
	}
}
