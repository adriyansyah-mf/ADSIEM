//go:build windows

package notify

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procWTSSendMessage = windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSSendMessageW")

const (
	mbOK            = 0x0
	mbIconWarning   = 0x30
	mbSetForeground = 0x10000
	mbTopmost       = 0x40000
	showSeconds     = 120 // the box closes itself after this
)

func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

func encodePowerShell(script string) string {
	runes := utf16.Encode([]rune(script))
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func buildToastScript(title, message, logoPath string) string {
	lines := strings.Split(message, "\n")
	line1 := ""
	line2 := ""
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if line1 == "" {
			line1 = l
		} else if line2 == "" {
			line2 = l
		} else {
			line2 += " - " + l
		}
	}

	escapedTitle := escapeXML(title)
	escapedLine1 := escapeXML(line1)
	escapedLine2 := escapeXML(line2)

	imageXML := ""
	if logoPath != "" {
		if _, err := os.Stat(logoPath); err == nil {
			imageXML = fmt.Sprintf(`<image placement="appLogoOverride" hint-crop="circle" src="%s"/>`, escapeXML(logoPath))
		}
	}

	xml := fmt.Sprintf(`
<toast duration="long">
  <visual>
    <binding template="ToastGeneric">
      %s
      <text>%s</text>
      <text>%s</text>
      <text>%s</text>
    </binding>
  </visual>
  <audio src="ms-winsoundevent:Notification.Default"/>
</toast>`, imageXML, escapedTitle, escapedLine1, escapedLine2)

	return fmt.Sprintf(`
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$template = @"
%s
"@
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($template)
$toast = [Windows.UI.Notifications.ToastNotification]::new($doc)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("ADSIEM").Show($toast)
`, xml)
}

// launchToastInSession runs PowerShell in the interactive user's session using WTSQueryUserToken
func launchToastInSession(sessionID uint32, psEncoded string) error {
	var token windows.Token
	err := windows.WTSQueryUserToken(sessionID, &token)
	if err != nil {
		return fmt.Errorf("WTSQueryUserToken: %w", err)
	}
	defer token.Close()

	var primaryToken windows.Token
	err = windows.DuplicateTokenEx(
		token,
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityIdentification,
		windows.TokenPrimary,
		&primaryToken,
	)
	if err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer primaryToken.Close()

	cmdLine, err := windows.UTF16PtrFromString(
		fmt.Sprintf(`powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand %s`, psEncoded),
	)
	if err != nil {
		return err
	}

	si := new(windows.StartupInfo)
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE
	pi := new(windows.ProcessInformation)

	err = windows.CreateProcessAsUser(
		primaryToken,
		nil,
		cmdLine,
		nil,
		nil,
		false,
		windows.CREATE_NO_WINDOW|windows.NORMAL_PRIORITY_CLASS,
		nil,
		nil,
		si,
		pi,
	)
	if err != nil {
		return fmt.Errorf("CreateProcessAsUser: %w", err)
	}

	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)
	return nil
}

var platformShow = func(title, message string) error {
	logo := EnsureLogo()
	psScript := buildToastScript(title, message, logo)
	psEncoded := encodePowerShell(psScript)

	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		// If WTSEnumerateSessions fails (e.g. standalone test mode), try direct exec
		cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-EncodedCommand", psEncoded)
		return cmd.Start()
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	list := unsafe.Slice(sessions, count)

	t, err := windows.UTF16FromString(title)
	if err != nil {
		return err
	}
	m, err := windows.UTF16FromString(message)
	if err != nil {
		return err
	}

	shown := 0
	for _, s := range list {
		if s.State != windows.WTSActive || s.SessionID == 0 {
			continue
		}

		// 1. Try modern Windows 10/11 Toast Notification in user session
		toastErr := launchToastInSession(s.SessionID, psEncoded)
		if toastErr == nil {
			shown++
			continue
		}
		slog.Debug("modern toast failed, falling back to message box", "session", s.SessionID, "err", toastErr)

		// 2. Fallback to WTSSendMessage if modern toast fails
		var response uint32
		r, _, callErr := procWTSSendMessage.Call(0, uintptr(s.SessionID),
			uintptr(unsafe.Pointer(&t[0])), uintptr(2*(len(t)-1)),
			uintptr(unsafe.Pointer(&m[0])), uintptr(2*(len(m)-1)),
			mbOK|mbIconWarning|mbSetForeground|mbTopmost, showSeconds,
			uintptr(unsafe.Pointer(&response)), 0)
		if r == 0 {
			err = callErr
			continue
		}
		shown++
	}

	if shown == 0 && err != nil {
		return fmt.Errorf("platformShow: %w", err)
	}
	return nil
}
