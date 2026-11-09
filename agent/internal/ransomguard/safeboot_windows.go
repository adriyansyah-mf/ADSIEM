//go:build windows

package ransomguard

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

// regBootStore is HKLM.
type regBootStore struct{}

func (regBootStore) get(key string) (string, bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	defer k.Close()
	v, _, err := k.GetStringValue("")
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	return v, err == nil, err
}

func (regBootStore) set(key, value string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("", value)
}

func (regBootStore) del(key string) error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, key)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return err
}

var platformBootStore bootStore = regBootStore{}
