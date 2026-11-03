//go:build !linux && !windows

package fullscan

func lowPriority() func() { return func() {} }
