//go:build linux

package webblock

import (
	"net"
	"os"
	"testing"
)

func TestClientProcessFindsOwnSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			c.Read(make([]byte, 1))
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pid, name := clientProcess(conn.LocalAddr().String())
	if pid != os.Getpid() || name == "" {
		t.Fatalf("pid %d name %q", pid, name)
	}
	if pid, name := clientProcess("garbage"); pid != 0 || name != "" {
		t.Fatal("garbage resolved")
	}
}

func TestHexAddr(t *testing.T) {
	if got := hexAddr(net.ParseIP("127.84.0.1").To4()); got != "0100547F" {
		t.Fatal(got)
	}
}
