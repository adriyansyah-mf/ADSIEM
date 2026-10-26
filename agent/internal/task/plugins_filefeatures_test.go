package task

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fileFeatures(t *testing.T, args map[string]any) map[string]any {
	t.Helper()
	var rows []map[string]any
	if err := pluginFileFeatures(context.Background(), args, func(r map[string]any) error {
		rows = append(rows, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want one row, got %d", len(rows))
	}
	return rows[0]
}

func TestFileFeaturesPE(t *testing.T) {
	path := filepath.Join("..", "yara", "testdata", "differential", "fixtures", "dll32.dll")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skip("fixture missing:", err)
	}
	row := fileFeatures(t, map[string]any{"path": path})
	sum := sha256.Sum256(data)
	if row["SHA256"] != hex.EncodeToString(sum[:]) || row["Type"] != "PE32" {
		t.Fatalf("hash/type: %v %v", row["SHA256"], row["Type"])
	}
	if secs, _ := row["Sections"].([]map[string]any); len(secs) == 0 {
		t.Error("no sections")
	}
	if _, ok := row["HasSignature"].(bool); !ok {
		t.Error("HasSignature missing")
	}
	if exports, _ := row["Exports"].([]string); len(exports) == 0 {
		t.Error("a DLL fixture should list its exports")
	}
	pe64 := fileFeatures(t, map[string]any{"path": filepath.Join(filepath.Dir(path), "pe64.exe")})
	if pe64["Type"] != "PE32+" {
		t.Errorf("pe64.exe: %v", pe64["Type"])
	}
}

func TestFileFeaturesELF(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the test binary is ELF only on Linux")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	row := fileFeatures(t, map[string]any{"path": self, "max_strings": 50})
	if row["Type"] != "ELF" || row["Machine"] == "" {
		t.Fatalf("type/machine: %v %v", row["Type"], row["Machine"])
	}
	strs := row["Strings"].([]map[string]any)
	if len(strs) == 0 || len(strs) > 50 {
		t.Errorf("strings capped at 50, got %d", len(strs))
	}
	for i := 1; i < len(strs); i++ {
		if strs[i]["Offset"].(int) < strs[i-1]["Offset"].(int) {
			t.Fatal("strings are in file order")
		}
	}
}

func TestFileFeaturesRedactsCredentialsAndFindsMarkers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dropper.bin")
	body := "\x00\x01junk\x00powershell -enc SQBFAFgA\x00AKIAABCDEFGHIJKLMNOP\x00" +
		"C:\\build\\stage2\\Release\\loader.pdb\x00UPX!\x00\x00" + string([]byte{'h', 0, 't', 0, 't', 0, 'p', 0, ':', 0, '/', 0, '/', 0, 'c', 0, '2', 0, 0, 0})
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	row := fileFeatures(t, map[string]any{"path": path, "max_size": 1 << 20})
	all := ""
	for _, s := range row["Strings"].([]map[string]any) {
		all += s["Encoding"].(string) + ":" + s["Value"].(string) + "\n"
	}
	if strings.Contains(all, "AKIAABCDEFGHIJKLMNOP") || row["Redacted"].(int) != 1 {
		t.Fatalf("credential must be redacted on the host: %q", all)
	}
	if !strings.Contains(all, "ascii:powershell -enc SQBFAFgA") || !strings.Contains(all, "utf16le:http://c2") {
		t.Errorf("strings: %q", all)
	}
	if pdb := row["PDB"].([]string); len(pdb) != 1 || !strings.HasSuffix(pdb[0], "loader.pdb") {
		t.Errorf("pdb: %v", pdb)
	}
	if p := row["PackerIndicators"].([]string); len(p) == 0 || p[0] != "UPX! marker" {
		t.Errorf("packer: %v", p)
	}
	if row["Type"] != "data" {
		t.Errorf("type: %v", row["Type"])
	}
}

func TestFileFeaturesHashesWholeFileButAnalysesPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.txt")
	data := []byte(strings.Repeat("A", 4096) + "TAILMARKER-not-analysed")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	row := fileFeatures(t, map[string]any{"path": path, "max_size": 4096})
	sum := sha256.Sum256(data)
	if row["SHA256"] != hex.EncodeToString(sum[:]) || row["Truncated"] != true {
		t.Fatal("hash covers the whole file; analysis is marked truncated")
	}
	for _, s := range row["Strings"].([]map[string]any) {
		if strings.Contains(s["Value"].(string), "TAILMARKER") {
			t.Fatal("bytes past max_size are not analysed")
		}
	}
	if err := pluginFileFeatures(context.Background(), map[string]any{"path": t.TempDir()},
		func(map[string]any) error { return nil }); err == nil {
		t.Fatal("a directory is refused")
	}
}
