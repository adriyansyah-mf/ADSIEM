// Command htmlfeat writes the HTML model's feature vectors (mlscore.ExtractHTML)
// for training (ml/html/train.py), so training and the agent share one
// feature extractor.
//
//	htmlfeat -malshare /path/malshare -warc a.warc.gz,b.warc.gz -out vectors.jsonl
//
// -malshare: a directory of <sha256>.zip (password "infected") and
// manifest.jsonl as ml/bench/fetch_malshare.py writes it; rows with
// file_type html are read, in memory only, label 1.
// -warc: Common Crawl WARC files; HTML responses with status 200, label 0.
//
// Each line: {"label", "src", "group", "sha256", "x"}. group keeps related
// pages together for a split: the host for crawled pages, the page's tag
// skeleton for samples (variants of one kit share it).
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime/pprof"
	"strconv"
	"strings"

	"github.com/siem-platform/agent/internal/mlscore"
	"github.com/siem-platform/agent/internal/zipcrypto"
)

type row struct {
	Label  int       `json:"label"`
	Src    string    `json:"src"`
	Group  string    `json:"group"`
	SHA256 string    `json:"sha256"`
	X      []float64 `json:"x"`
}

var reTagName = regexp.MustCompile(`<([a-zA-Z][a-zA-Z0-9]{0,15})`)

// skeleton hashes the first 300 tag names: pages built from one template share it.
func skeleton(b []byte) string {
	var names []string
	for _, m := range reTagName.FindAllSubmatch(b, 300) {
		names = append(names, strings.ToLower(string(m[1])))
	}
	h := sha1.Sum([]byte(strings.Join(names, ",")))
	return hex.EncodeToString(h[:6])
}

func main() {
	malshare := flag.String("malshare", "", "MalShare sample directory (manifest.jsonl + <sha>.zip)")
	warcs := flag.String("warc", "", "comma-separated Common Crawl WARC files")
	perWARC := flag.Int("per-warc", 30000, "HTML pages to take from each WARC")
	out := flag.String("out", "vectors.jsonl", "output JSONL")
	cpuprofile := flag.String("cpuprofile", "", "write a CPU profile here")
	flag.Parse()
	if *cpuprofile != "" {
		pf, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		if err := pprof.StartCPUProfile(pf); err != nil {
			log.Fatal(err)
		}
		defer pprof.StopCPUProfile()
	}

	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	enc := json.NewEncoder(w)
	seen := map[string]bool{}
	emit := func(label int, src, group string, b []byte) {
		sum := sha256.Sum256(b)
		sha := hex.EncodeToString(sum[:])
		if seen[sha] {
			return
		}
		seen[sha] = true
		if err := enc.Encode(row{label, src, group, sha, mlscore.ExtractHTML(b)}); err != nil {
			log.Fatal(err)
		}
	}

	if *malshare != "" {
		n, err := readMalShare(*malshare, func(b []byte) { emit(1, "malshare", "s:"+skeleton(b), b) })
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("malshare: %d html samples", n)
	}
	for _, p := range strings.Split(*warcs, ",") {
		if p == "" {
			continue
		}
		n, err := readWARC(p, *perWARC, func(host string, b []byte) { emit(0, "commoncrawl", "h:"+host, b) })
		if err != nil {
			log.Fatalf("%s: %v", p, err)
		}
		log.Printf("%s: %d html pages", filepath.Base(p), n)
	}
}

func readMalShare(dir string, fn func([]byte)) (int, error) {
	mf, err := os.Open(filepath.Join(dir, "manifest.jsonl"))
	if err != nil {
		return 0, err
	}
	defer mf.Close()
	sc := bufio.NewScanner(mf)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		var m struct {
			SHA256   string `json:"sha256_hash"`
			FileType string `json:"file_type"`
		}
		if json.Unmarshal(sc.Bytes(), &m) != nil || m.FileType != "html" {
			continue
		}
		b, err := sample(filepath.Join(dir, m.SHA256+".zip"), m.SHA256)
		if err != nil {
			log.Printf("%s: %v", m.SHA256, err)
			continue
		}
		fn(b)
		n++
	}
	return n, sc.Err()
}

func sample(path, sha string) ([]byte, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	for _, zf := range r.File {
		b, err := zipcrypto.ReadFile(zf, []byte("infected"), 64<<20)
		if err != nil {
			return nil, err
		}
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) == sha {
			return b, nil
		}
	}
	return nil, fmt.Errorf("no entry with sha256 %s", sha)
}

// readWARC calls fn with the body of each HTML response (status 200).
func readWARC(path string, limit int, fn func(host string, body []byte)) (int, error) {
	fh, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer fh.Close()
	gz, err := gzip.NewReader(fh) // multistream: one member per record
	if err != nil {
		return 0, err
	}
	br := bufio.NewReaderSize(gz, 1<<20)
	n := 0
	for n < limit {
		hdr, err := readHeaders(br)
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		length, _ := strconv.Atoi(hdr["content-length"])
		block := make([]byte, length)
		if _, err := io.ReadFull(br, block); err != nil {
			return n, err
		}
		if hdr["warc-type"] != "response" {
			continue
		}
		i := bytes.Index(block, []byte("\r\n\r\n"))
		if i < 0 {
			continue
		}
		head := strings.ToLower(string(block[:i]))
		body := block[i+4:]
		if !strings.HasPrefix(head, "http/1.1 200") && !strings.HasPrefix(head, "http/1.0 200") && !strings.HasPrefix(head, "http/2 200") {
			continue
		}
		if !strings.Contains(head, "content-type: text/html") || strings.Contains(head, "\ncontent-encoding: ") || len(body) < 200 {
			continue
		}
		host := ""
		if u, err := url.Parse(hdr["warc-target-uri"]); err == nil {
			host = u.Hostname()
		}
		fn(host, body)
		n++
	}
	return n, nil
}

func readHeaders(br *bufio.Reader) (map[string]string, error) {
	h := map[string]string{}
	started := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if err == io.EOF && !started {
				return nil, io.EOF
			}
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if started {
				return h, nil
			}
			continue // blank lines between records
		}
		if !started {
			if !strings.HasPrefix(line, "WARC/") {
				return nil, fmt.Errorf("not a WARC record: %q", line)
			}
			started = true
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			h[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
}
