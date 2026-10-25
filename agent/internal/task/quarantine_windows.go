//go:build windows

package task

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// Quarantine on Windows locks the file where it is, like Linux: its DACL is
// replaced by one that grants only SYSTEM, inheritance is cut off, and the
// owner moves to SYSTEM so the previous owner cannot simply grant itself
// access again. Nothing is moved, so it works for files on any volume and for
// files in use (open handles keep their access; nothing new can open, run or
// load it). The original DACL and owner go to the agent's state file, and
// restore_file puts them back.

const lockedDACL = "D:P(A;;FA;;;SY)" // protected: full access for SYSTEM only

func quarantineFile(path string) (QuarantineRecord, error) {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return QuarantineRecord{}, err
	}
	if err := assertQuarantinable(abs); err != nil {
		return QuarantineRecord{}, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return QuarantineRecord{}, fmt.Errorf("quarantine_file: %w", err)
	}
	if info.IsDir() {
		return QuarantineRecord{}, fmt.Errorf("quarantine_file: %s is a directory", abs)
	}
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return QuarantineRecord{}, fmt.Errorf("quarantine_file: %s is a link or reparse point", abs)
	}

	qStore.mu.Lock()
	defer qStore.mu.Unlock()
	if prior, ok := qStore.load()[abs]; ok {
		return prior, nil // already locked: keep the original descriptor on record
	}

	sum, err := hashFile(abs)
	if err != nil {
		return QuarantineRecord{}, fmt.Errorf("quarantine_file: hash: %w", err)
	}
	sd, err := windows.GetNamedSecurityInfo(abs, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return QuarantineRecord{}, fmt.Errorf("quarantine_file: read security descriptor: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return QuarantineRecord{}, fmt.Errorf("quarantine_file: read owner: %w", err)
	}
	rec := QuarantineRecord{
		Path: abs, Size: info.Size(), SHA256: sum, QuarantinedAt: time.Now().UTC(),
		OriginalDACL: sd.String(), OriginalOwner: owner.String(), Immutable: true,
	}

	locked, err := windows.SecurityDescriptorFromString(lockedDACL)
	if err != nil {
		return QuarantineRecord{}, err
	}
	dacl, _, err := locked.DACL()
	if err != nil {
		return QuarantineRecord{}, err
	}
	if err := windows.SetNamedSecurityInfo(abs, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return QuarantineRecord{}, fmt.Errorf("quarantine_file: lock DACL: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err == nil {
		err = withPrivileges(func() error {
			return windows.SetNamedSecurityInfo(abs, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, system, nil, nil, nil)
		}, "SeRestorePrivilege", "SeTakeOwnershipPrivilege")
	}
	if err == nil {
		rec.OwnerChanged = true
	} else {
		slog.Warn("quarantine_file: owner not moved to SYSTEM; the DACL is locked", "path", abs, "err", err)
	}

	qStore.load()[abs] = rec
	qStore.save()
	return rec, nil
}

func restoreFile(path string) (QuarantineRecord, error) {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return QuarantineRecord{}, err
	}
	qStore.mu.Lock()
	defer qStore.mu.Unlock()
	rec, ok := qStore.load()[abs]
	if !ok {
		return QuarantineRecord{}, fmt.Errorf("restore_file: %s is not quarantined", abs)
	}

	original, err := windows.SecurityDescriptorFromString(rec.OriginalDACL)
	if err != nil {
		return QuarantineRecord{}, fmt.Errorf("restore_file: recorded descriptor: %w", err)
	}
	if rec.OwnerChanged { // the owner first: then whoever restores holds WRITE_DAC again
		owner, err := windows.StringToSid(rec.OriginalOwner)
		if err != nil {
			return QuarantineRecord{}, fmt.Errorf("restore_file: recorded owner: %w", err)
		}
		if err := withPrivileges(func() error {
			return windows.SetNamedSecurityInfo(abs, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil)
		}, "SeRestorePrivilege", "SeTakeOwnershipPrivilege"); err != nil {
			return QuarantineRecord{}, fmt.Errorf("restore_file: restore owner: %w", err)
		}
	}
	dacl, _, err := original.DACL()
	if err != nil {
		return QuarantineRecord{}, fmt.Errorf("restore_file: recorded DACL: %w", err)
	}
	control, _, err := original.Control()
	if err != nil {
		return QuarantineRecord{}, err
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		info = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := withPrivileges(func() error {
		return windows.SetNamedSecurityInfo(abs, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil)
	}, "SeRestorePrivilege"); err != nil {
		return QuarantineRecord{}, fmt.Errorf("restore_file: restore DACL: %w", err)
	}

	if sum, err := hashFile(abs); err == nil && sum != rec.SHA256 {
		slog.Warn("restored file content differs from quarantine hash", "path", abs, "expected", rec.SHA256, "actual", sum)
	}
	delete(qStore.entries, abs)
	qStore.save()
	return rec, nil
}

// assertQuarantinable refuses what would break Windows or the agent.
func assertQuarantinable(abs string) error {
	if vol := filepath.VolumeName(abs); abs == vol+`\` || abs == vol {
		return fmt.Errorf("quarantine_file: refusing to quarantine a drive root")
	}
	protected := []string{os.Getenv("SystemRoot")}
	if exe, err := os.Executable(); err == nil {
		protected = append(protected, filepath.Dir(exe))
	}
	if pd := os.Getenv("ProgramData"); pd != "" {
		protected = append(protected, filepath.Join(pd, "SIEMAgent"))
	}
	for _, dir := range protected {
		if dir == "" {
			continue
		}
		if strings.EqualFold(abs, dir) || strings.HasPrefix(strings.ToLower(abs), strings.ToLower(dir)+`\`) {
			return fmt.Errorf("quarantine_file: %s is under %s, which is protected", abs, dir)
		}
	}
	return nil
}

// withPrivileges runs fn with the named privileges enabled on the process
// token (SYSTEM and elevated administrators hold them, disabled).
func withPrivileges(fn func() error, names ...string) error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return fn()
	}
	defer token.Close()
	for _, name := range names {
		var luid windows.LUID
		p, err := windows.UTF16PtrFromString(name)
		if err != nil || windows.LookupPrivilegeValue(nil, p, &luid) != nil {
			continue
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1,
			Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
		_ = windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
	}
	return fn()
}
