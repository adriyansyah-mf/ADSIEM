// Command authsig prints who signed Windows programs: the Authenticode
// publisher (the value a prevention "signer" rule matches), organization and
// issuing CA, as internal/authenticode reads them. It runs on any OS.
//
//	go run ./cmd/authsig installer.exe other.exe
//	find . -name '*.exe' | go run ./cmd/authsig -
//
// Used to check the publisher names in the server's prevention rule pack
// against real binaries before adding them.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/siem-platform/agent/internal/authenticode"
)

type row struct {
	File         string `json:"file"`
	Publisher    string `json:"publisher,omitempty"`
	Organization string `json:"organization,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	Error        string `json:"error,omitempty"`
}

func main() {
	files := os.Args[1:]
	if len(files) == 1 && files[0] == "-" {
		files = nil
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			files = append(files, sc.Text())
		}
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "usage: authsig FILE... | authsig - < list")
		os.Exit(2)
	}
	out := json.NewEncoder(os.Stdout)
	for _, f := range files {
		r := row{File: f}
		if s, err := authenticode.ReadFile(f); err != nil {
			r.Error = err.Error()
		} else {
			r.Publisher, r.Organization, r.Issuer = s.Publisher, s.Organization, s.Issuer
		}
		_ = out.Encode(r)
	}
}
