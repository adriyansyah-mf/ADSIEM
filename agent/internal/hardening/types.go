package hardening

// Status is OS-agnostic — a future windows.go reports the same three-state
// result, so no schema change is needed to add that platform later.
type Status string

const (
	StatusPass          Status = "pass"
	StatusFail          Status = "fail"
	StatusNotApplicable Status = "not_applicable"
	StatusError         Status = "error"
)

type Check struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Status   Status `json:"status"`
	Detail   string `json:"detail"`
}

type Report struct {
	Checks []Check `json:"checks"`
}

// PortInfo mirrors the fields hygiene.OpenPort already carries. Kept as a
// separate type so this package never imports hygiene — hygiene imports
// hardening (to attach checks to its report), not the other way around.
type PortInfo struct {
	Port  int
	Proto string
	State string
}
