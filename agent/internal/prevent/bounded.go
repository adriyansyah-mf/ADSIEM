package prevent

// matchBounded is p.Match where only the hash waits for one of slots: hashing
// a large executable (up to 256 MB) is the slow part, so a few concurrent
// hashes are allowed and the rest queue. Path, directory and parent rules
// read no file and are decided at once, also while every slot is busy:
// before, every process start took a slot first, so a burst of large hashes
// delayed the kill of an unrelated path-rule match.
// sum is the SHA-256 when the hash was computed.
func matchBounded(p *Policy, path, parent string, slots chan struct{}, hash func(string) (string, error)) (c *compiled, sum string) {
	c = p.Match(Exec{Path: path, Parent: parent, Hash: func() (string, bool) {
		slots <- struct{}{}
		defer func() { <-slots }()
		h, err := hash(path)
		sum = h
		return h, err == nil
	}}, false)
	return c, sum
}
