//go:build !windows

package ransomguard

// originalFilename: PE version resources are a Windows thing.
var originalFilename func(string) string
