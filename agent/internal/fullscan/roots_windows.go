package fullscan

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func quickRoots() []string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	users := drive + `\Users\*`
	return []string{
		filepath.Join(root, "Temp"),
		users + `\Downloads`, users + `\Desktop`, users + `\Documents`,
		users + `\AppData\Local\Temp`, users + `\AppData\Roaming`,
		users + `\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`,
		drive + `\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`,
		drive + `\Users\Public`, drive + `\ProgramData`, drive + `\inetpub\wwwroot`,
	}
}

// fullRoots: every local fixed disk.
func fullRoots() []string {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return []string{os.Getenv("SystemDrive") + `\`}
	}
	var out []string
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		p, err := windows.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		if windows.GetDriveType(p) == windows.DRIVE_FIXED {
			out = append(out, root)
		}
	}
	return out
}

func skippedMounts() map[string]bool { return map[string]bool{} }

// skipDir: component store copies of system files (hard links of what
// System32 holds, hundreds of thousands) and folders the system denies.
func skipDir(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "winsxs", "system volume information", "$windows.~bt", "$windows.~ws":
		return true
	}
	return false
}
