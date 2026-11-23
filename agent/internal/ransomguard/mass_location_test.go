package ransomguard

import (
	"fmt"
	"strings"
	"testing"
)

// churn is a browser-cache pattern: many new entries across many folders,
// old ones evicted, from one process in one window.
func churn(d *detector, pid uint32, root, sep string) *finding {
	var f *finding
	for i := 0; i < 2*minWrites; i++ {
		p := strings.Join([]string{root, fmt.Sprintf("d%02d", i%(2*minWriteDirs)), fmt.Sprintf("%040X", i)}, sep)
		if got := d.observe(ev(pid, "create", p, "", 0)); got != nil {
			f = got
		}
		if i%2 == 0 {
			if got := d.observe(ev(pid, "delete", p+"-old", "", 0)); got != nil {
				f = got
			}
		}
	}
	return f
}

// Firefox (Microsoft Store build) churning its cache2 killed the browser and
// tried to isolate the host: mass_modify counted writes anywhere, and brotli
// cache bodies have no header, so they read as encrypted.
func TestMassModifyIgnoresCachesAndProgramState(t *testing.T) {
	quiet := []string{
		`C:\Users\wonka\AppData\Local\Packages\Mozilla.Firefox_n80bbvh6b1yt2\LocalCache\Local\Mozilla\Firefox\Profiles\w3s2fxxt.default-release\cache2\entries`,
		`C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data`,
		`C:\Users\bob\AppData\Local\Temp\build`, `C:\Windows\SoftwareDistribution\Download`,
		`C:\Program Files\App\cache`, `C:\ProgramData\Vendor\db`,
		"/home/alice/.cache/mozilla/firefox/x.default/cache2/entries", "/home/alice/.mozilla/firefox/x/storage",
		"/tmp/build", "/var/cache/apt/archives", "/var/tmp/x",
	}
	for i, root := range quiet {
		sep := "/"
		if strings.Contains(root, `\`) {
			sep = `\`
		}
		if f := churn(newDetector(nil), uint32(100+i), root, sep); f != nil && f.kind == "mass_modify" {
			t.Errorf("%s: fired %+v", root, f)
		}
	}
}

func TestMassModifyStillFiresOnDataAnywhereElse(t *testing.T) {
	fires := []string{
		`C:\Users\bob\Documents`, `D:\Projects`, `\\fs01\share\dept`,
		"/home/alice/docs", "/srv/share", "/var/lib/mysql", "/opt/app/data",
	}
	for i, root := range fires {
		sep := "/"
		if strings.Contains(root, `\`) {
			sep = `\`
		}
		if f := churn(newDetector(nil), uint32(200+i), root, sep); f == nil || f.kind != "mass_modify" {
			t.Errorf("%s: no mass_modify (%+v)", root, f)
		}
	}
}

// A process writing documents and its own cache: the entropy sample must be
// the documents, not the cache entries written last.
func TestMassModifySamplesDataNotCache(t *testing.T) {
	d := newDetector(nil)
	var f *finding
	for i := 0; i < minWrites; i++ {
		doc := fmt.Sprintf(`C:\Users\bob\Documents\d%d\f%d.docx`, i%minWriteDirs, i)
		if got := d.observe(ev(300, "create", doc, "", 0)); got != nil {
			f = got
		}
		if i < minDestructive {
			if got := d.observe(ev(300, "delete", doc+".orig", "", 0)); got != nil {
				f = got
			}
		}
		if got := d.observe(ev(300, "write", fmt.Sprintf(`C:\Users\bob\AppData\Local\App\cache\%d`, i), "", 0)); got != nil {
			f = got
		}
	}
	if f == nil || f.kind != "mass_modify" {
		t.Fatalf("finding = %+v", f)
	}
	for _, p := range f.targets {
		if strings.Contains(strings.ToLower(p), `\appdata\`) {
			t.Fatalf("cache entry sampled: %v", f.targets)
		}
	}
}
