//go:build !linux && !windows

package memscan

import "errors"

var errUnsupported = errors.New("memscan: Linux and Windows only")

type Reader interface {
	ReadAt(p []byte, addr uint64) (int, error)
	Close() error
}

func Regions(int) ([]Region, error) { return nil, errUnsupported }
func Open(int) (Reader, error)      { return nil, errUnsupported }
func ProcessImage(int) string       { return "" }
func Processes() ([]Proc, error)    { return nil, errUnsupported }
