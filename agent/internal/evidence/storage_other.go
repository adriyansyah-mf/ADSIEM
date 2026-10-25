//go:build !linux && !windows

package evidence

import "os"

type storageDir struct{}

func openStorageDir(string) (*storageDir, error)       { return nil, ErrUnsupported }
func (*storageDir) open(string, int) (*os.File, error) { return nil, ErrUnsupported }
func (*storageDir) names() ([]string, error)           { return nil, ErrUnsupported }
func (*storageDir) lock() (*os.File, error)            { return nil, ErrUnsupported }
func (*storageDir) sync() error                        { return ErrUnsupported }
func (*storageDir) close() error                       { return nil }
func (*storageDir) remove(string) error                { return ErrUnsupported }
