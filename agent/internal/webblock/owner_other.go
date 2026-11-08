//go:build !linux && !windows

package webblock

func clientProcess(remoteAddr string) (int, string) { return 0, "" }
