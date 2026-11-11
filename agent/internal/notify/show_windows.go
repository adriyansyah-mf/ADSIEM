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

	// toastAUMID is the AppUserModelID the toast is sent under. An unpackaged
	// app has to register it (HKCU\Software\Classes\AppUserModelId\<id>),
	// otherwise Windows drops the toast without any error.
	toastAUMID = "ADSIEM.Agent"
	// toastWaitMs bounds how long we wait for PowerShell to report whether
	// the toast went out before falling back to the message box.
	toastWaitMs = 30_000
)

func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

// psQuote makes s safe inside a single-quoted PowerShell string.
func psQuote(s string) string { return strings.ReplaceAll(s, "'", "''") }

func encodePowerShell(script string) string {
	runes := utf16.Encode([]rune(script))
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func toastXML(title, message, logoPath string) string {
	line1, line2 := "", ""
	for _, l := range strings.Split(message, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "":
		case line1 == "":
			line1 = l
		case line2 == "":
			line2 = l
		default:
			line2 += " - " + l
		}
	}

	imageXML := ""
	if logoPath != "" {
		if _, err := os.Stat(logoPath); err == nil {
			uri := "file:///" + strings.ReplaceAll(logoPath, `\`, "/")
			imageXML = fmt.Sprintf(`<image placement="appLogoOverride" hint-crop="circle" src="%s"/>`, escapeXML(uri))
		}
	}

	return fmt.Sprintf(`<toast duration="long" scenario="reminder">
  <visual>
    <binding template="ToastGeneric">
      %s
      <text>%s</text>
      <text>%s</text>
      <text>%s</text>
    </binding>
  </visual>
  <actions>
    <action content="OK" arguments="dismiss" activationType="system"/>
  </actions>
  <audio src="ms-winsoundevent:Notification.Default"/>
</toast>`, imageXML, escapeXML(title), escapeXML(line1), escapeXML(line2))
}

// buildToastScript returns a PowerShell script that registers the AUMID for
// the current user, shows the toast and exits 0 only when Windows accepted
// it. Any other exit code makes the caller fall back to the message box.
func buildToastScript(title, message, logoPath string) string {
	iconLine := ""
	if logoPath != "" {
		iconLine = fmt.Sprintf(`  New-ItemProperty -Path $key -Name IconUri -Value '%s' -PropertyType String -Force | Out-Null`, psQuote(logoPath))
	}
	// The XML goes in a single-quoted here-string so "$" in file paths
	// (C:\$Recycle.Bin\...) is not expanded; escapeXML already removed "'".
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
try {
  [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
  [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
  $aumid = '%s'
  $key = 'HKCU:\Software\Classes\AppUserModelId\' + $aumid
  if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
  New-ItemProperty -Path $key -Name DisplayName -Value 'ADSIEM' -PropertyType String -Force | Out-Null
%s
  $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($aumid)
  $setting = $null
  try { $setting = $notifier.Setting } catch {}
  if ($null -ne $setting -and $setting -ne [Windows.UI.Notifications.NotificationSetting]::Enabled) { exit 2 }
  $xml = @'
%s
'@
  $doc = New-Object Windows.Data.Xml.Dom.XmlDocument
  $doc.LoadXml($xml)
  $notifier.Show([Windows.UI.Notifications.ToastNotification]::new($doc))
  exit 0
} catch {
  exit 1
}
`, toastAUMID, iconLine, toastXML(title, message, logoPath))
}

func powershellCmdLine(psEncoded string) string {
	return `powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand ` + psEncoded
}

// launchToastInSession runs the toast script as the user signed in to
// sessionID and waits for its verdict: nil only when the toast was shown.
func launchToastInSession(sessionID uint32, psEncoded string) error {
	var token windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &token); err != nil {
		return fmt.Errorf("WTSQueryUserToken: %w", err)
	}
	defer token.Close()

	var primaryToken windows.Token
	if err := windows.DuplicateTokenEx(token, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityIdentification, windows.TokenPrimary, &primaryToken); err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer primaryToken.Close()

	// The user's own environment (USERPROFILE, APPDATA, ...), not SYSTEM's.
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, primaryToken, false); err != nil {
		env = nil
	} else {
		defer windows.DestroyEnvironmentBlock(env)
	}

	cmdLine, err := windows.UTF16PtrFromString(powershellCmdLine(psEncoded))
	if err != nil {
		return err
	}
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)

	si := new(windows.StartupInfo)
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Desktop = desktop
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE
	pi := new(windows.ProcessInformation)

	flags := uint32(windows.CREATE_NO_WINDOW | windows.NORMAL_PRIORITY_CLASS)
	if env != nil {
		flags |= windows.CREATE_UNICODE_ENVIRONMENT
	}
	if err := windows.CreateProcessAsUser(primaryToken, nil, cmdLine, nil, nil, false,
		flags, env, nil, si, pi); err != nil {
		return fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	ev, err := windows.WaitForSingleObject(pi.Process, toastWaitMs)
	if err != nil {
		return fmt.Errorf("wait toast: %w", err)
	}
	if ev != windows.WAIT_OBJECT_0 {
		_ = windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("toast script timed out")
	}
	var code uint32
	if err := windows.GetExitCodeProcess(pi.Process, &code); err != nil {
		return fmt.Errorf("toast exit code: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("toast not shown (exit %d)", code)
	}
	return nil
}

func sendMessageBox(sessionID uint32, t, m []uint16) error {
	var response uint32
	r, _, callErr := procWTSSendMessage.Call(0, uintptr(sessionID),
		uintptr(unsafe.Pointer(&t[0])), uintptr(2*(len(t)-1)),
		uintptr(unsafe.Pointer(&m[0])), uintptr(2*(len(m)-1)),
		mbOK|mbIconWarning|mbSetForeground|mbTopmost, showSeconds,
		uintptr(unsafe.Pointer(&response)), 0) // bWait FALSE: do not wait for the user
	if r == 0 {
		return fmt.Errorf("WTSSendMessage: %w", callErr)
	}
	return nil
}

var platformShow = func(title, message string) error {
	psEncoded := encodePowerShell(buildToastScript(title, message, EnsureLogo()))

	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		// Not a service (dev run in a user console): show it directly.
		return exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
			"-ExecutionPolicy", "Bypass", "-EncodedCommand", psEncoded).Run()
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
	var lastErr error
	for _, s := range list {
		if s.State != windows.WTSActive || s.SessionID == 0 {
			continue
		}
		toastErr := launchToastInSession(s.SessionID, psEncoded)
		if toastErr == nil {
			shown++
			continue
		}
		slog.Info("notify: toast failed, using message box", "session", s.SessionID, "err", toastErr)
		if err := sendMessageBox(s.SessionID, t, m); err != nil {
			lastErr = err
			continue
		}
		shown++
	}
	if shown == 0 && lastErr != nil {
		return lastErr
	}
	return nil
}
