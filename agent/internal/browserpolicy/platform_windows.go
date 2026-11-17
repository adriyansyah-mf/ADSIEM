//go:build windows

package browserpolicy

import (
	"errors"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/windows/registry"
)

// New is the applier for this OS: HKLM policies on Windows.
func New(stateDir string) Applier {
	return &RegistryApplier{Reg: hklm{}, StatePath: filepath.Join(stateDir, "browser_policy.json")}
}

// hklm is Registry over HKEY_LOCAL_MACHINE (the 64-bit view, where browsers read policies).
type hklm struct{}

func (hklm) Get(key, name string) (string, bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	defer k.Close()
	_, typ, err := k.GetValue(name, nil)
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	if err != nil && !errors.Is(err, registry.ErrShortBuffer) {
		return "", false, err
	}
	switch typ {
	case registry.DWORD, registry.QWORD:
		n, _, err := k.GetIntegerValue(name)
		if err != nil {
			return "", false, err
		}
		return strconv.FormatUint(n, 10), true, nil
	default:
		s, _, err := k.GetStringValue(name)
		if err != nil {
			return "", true, nil // present, some other type: an administrator's, not equal to ours
		}
		return s, true, nil
	}
}

func (hklm) create(key string) (registry.Key, error) {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE|registry.WOW64_64KEY)
	return k, err
}

func (h hklm) SetString(key, name, value string) error {
	k, err := h.create(key)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(name, value)
}

func (h hklm) SetDWORD(key, name string, value uint32) error {
	k, err := h.create(key)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(name, value)
}

func (hklm) Delete(key, name string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}
