package prevent

// matchBounded is p.Match where only the hash waits for one of slots: hashing
// a large executable (up to 256 MB) is the slow part, so a few concurrent
// hashes are allowed and the rest queue. Path, directory and parent rules
// read no file and are decided at once, also while every slot is busy:
// before, every process start took a slot first, so a burst of large hashes
// delayed the kill of an unrelated path-rule match.
// sum is the SHA-256 when the hash was computed. signer, when set, reads the
// file's Authenticode publisher (it reads the file too, so it takes a slot);
// publisher is what it returned.
func matchBounded(p *Policy, path, parent string, slots chan struct{}, hash func(string) (string, error),
	signer func(string) (string, error)) (c *compiled, sum, publisher string) {
	e := Exec{Path: path, Parent: parent, Hash: func() (string, bool) {
		slots <- struct{}{}
		defer func() { <-slots }()
		h, err := hash(path)
		sum = h
		return h, err == nil
	}}
	if signer != nil {
		e.Signer = func() (string, bool) {
			slots <- struct{}{}
			defer func() { <-slots }()
			s, err := signer(path)
			publisher = s
			return s, err == nil
		}
	}
	c = p.Match(e, false)
	return c, sum, publisher
}
