// Command winevent-fmt is a test tool for the SigmaHQ regression harness
// (tests/sigmahq): it reads JSONL records with an "xml" array of rendered
// Windows events and writes them back with "lines" — exactly what the agent
// ships for each event (winevent.FormatXML).
package main

import (
	"bufio"
	"encoding/json"
	"os"

	"github.com/siem-platform/agent/internal/winevent"
)

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 64<<20), 64<<20)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(in.Bytes(), &rec); err != nil {
			panic(err)
		}
		var lines []string
		for _, x := range rec["xml"].([]any) {
			line, err := winevent.FormatXML([]byte(x.(string)))
			if err != nil {
				line = "FORMAT_ERROR " + err.Error()
			}
			lines = append(lines, line)
		}
		delete(rec, "xml")
		rec["lines"] = lines
		_ = out.Encode(rec)
	}
}
