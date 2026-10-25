//go:build windows

package update

import "testing"

func TestPackedUpgradeCode(t *testing.T) {
	if got := packedGUID(upgradeCode); got != "786259F0C12E613499139D9A4CEFF72A" {
		t.Fatalf("packed %s", got)
	}
}
