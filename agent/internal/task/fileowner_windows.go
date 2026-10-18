//go:build windows

package task

import "io/fs"

// fileOwnerUID: NTFS owners are SIDs behind an ACL lookup per file, which a
// bulk glob shouldn't pay for; Windows rows leave Uid empty.
func fileOwnerUID(fs.FileInfo) string { return "" }
