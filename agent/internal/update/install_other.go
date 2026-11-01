//go:build !linux && !windows

package update

import (
	"context"
	"errors"
)

func DetectKind() (string, error) { return "", errors.New("updates are not supported on this OS") }

func InstallPackage(ctx context.Context, kind, pkg, logPath string) error {
	return errors.New("updates are not supported on this OS")
}
