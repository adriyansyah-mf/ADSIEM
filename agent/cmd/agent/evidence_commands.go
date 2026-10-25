package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/siem-platform/agent/internal/config"
	"github.com/siem-platform/agent/internal/evidence"
)

// evidenceCommand is an offline operator action on the local evidence
// journal: list parked (held or quarantined) evidence, release it for
// delivery, or discard it. The agent must be stopped: the journal belongs to
// one process at a time.
type evidenceCommand struct {
	list             bool
	release, discard string
	salvage          bool
	reason           string
	yes              bool
}

func (c evidenceCommand) requested() bool {
	return c.list || c.release != "" || c.discard != "" || c.salvage
}

// checkOperator refuses anyone but the service identity's peers (root,
// elevated Administrator / SYSTEM); tests replace it.
var checkOperator = operatorIdentity

func runEvidenceCommand(cfg *config.Config, c evidenceCommand, out io.Writer) error {
	if c.release != "" && c.discard != "" {
		return errors.New("use one of -evidence-release and -evidence-discard")
	}
	action, eventID := "", ""
	switch {
	case c.release != "":
		action, eventID = "release", c.release
	case c.discard != "":
		action, eventID = "discard", c.discard
	}
	if c.salvage && (action != "" || c.list) {
		return errors.New("-evidence-salvage runs on its own")
	}
	if (action != "" || c.salvage) && strings.TrimSpace(c.reason) == "" {
		return errors.New("-reason is required: it is kept in the journal's audit trail")
	}
	if err := checkOperator(); err != nil {
		return err
	}
	e := cfg.Evidence
	if _, err := os.Stat(e.Dir); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no evidence journal at %s (evidence.enabled has never run here)", e.Dir)
	}
	opts := evidence.Options{Dir: e.Dir, AgentID: cfg.Agent.ID, MaxBytes: e.MaxBytes,
		SegmentBytes: e.SegmentBytes, ReservedBytes: e.ReservedBytes, MaxEventBytes: e.MaxEventBytes}
	j, err := evidence.Open(opts)
	if errors.Is(err, evidence.ErrLocked) {
		return errors.New("the agent is running: stop the service first, operator actions need the journal offline")
	}
	if c.salvage {
		if err == nil {
			j.Close()
			return fmt.Errorf("the journal at %s opens normally: nothing to salvage", e.Dir)
		}
		return salvageJournal(opts, strings.TrimSpace(c.reason), err, out)
	}
	if err != nil {
		return fmt.Errorf("open evidence journal: %w", err)
	}
	defer j.Close()
	ctx := context.Background()

	if action == "" {
		return listEvidence(ctx, j, out)
	}
	err = j.Resolve(ctx, eventID, action, strings.TrimSpace(c.reason), c.yes)
	switch {
	case errors.Is(err, evidence.ErrDuplicateRisk):
		return fmt.Errorf("event %s was sent without a confirmed receipt for 30 days: the server may already "+
			"have processed it, and releasing it can repeat its detections and automated responses. "+
			"Re-run with -yes to release it anyway", eventID)
	case errors.Is(err, evidence.ErrUnknownEvent):
		return fmt.Errorf("event %s is not in the journal (or was already delivered)", eventID)
	case errors.Is(err, evidence.ErrNotResolvable):
		return fmt.Errorf("event %s is waiting for delivery, not held or quarantined: nothing to resolve", eventID)
	case err != nil:
		return err
	}
	if action == "release" {
		fmt.Fprintf(out, "released %s: it will be delivered when the agent runs again (recorded in the journal audit)\n", eventID)
	} else {
		fmt.Fprintf(out, "discarded %s: it will not be delivered (recorded in the journal audit)\n", eventID)
	}
	return nil
}

// listEvidence prints metadata only: never raw events or credentials.
func listEvidence(ctx context.Context, j *evidence.Journal, out io.Writer) error {
	records, pending, err := j.Records(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%d event(s) waiting for delivery, %d held or quarantined\n", pending, len(records))
	if len(records) > 0 {
		w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "EVENT ID\tSTATE\tREASON\tCOLLECTED\tFIRST SENT\tBYTES\tLOG TYPE")
		for _, r := range records {
			first := "never"
			if !r.FirstAttempt.IsZero() {
				first = r.FirstAttempt.Format(time.RFC3339)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n", r.EventID, r.State, r.Reason,
				r.CollectedAt.UTC().Format(time.RFC3339), first, r.Bytes, r.LogType)
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}
	if audit := j.Audit(); len(audit) > 0 {
		fmt.Fprintln(out, "\nrecent operator actions:")
		start := max(0, len(audit)-10)
		for _, a := range audit[start:] {
			fmt.Fprintf(out, "  %s  %s %s (was %s): %s\n", a.At.Format(time.RFC3339), a.Action, a.EventID, a.PriorState, a.Reason)
		}
	}
	return nil
}

// salvageJournal replaces a journal that does not open with a new one holding
// its readable undelivered evidence and cursors (evidence.Salvage). The old
// directory is kept beside it as <dir>.corrupt-<time>, untouched, and a JSON
// report with the operator's reason goes to the state directory.
func salvageJournal(opts evidence.Options, reason string, openErr error, out io.Writer) error {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	target, kept := opts.Dir+".salvage-"+stamp, opts.Dir+".corrupt-"+stamp
	report, err := evidence.Salvage(context.Background(), opts, target)
	if err != nil {
		_ = os.RemoveAll(target) // only the directory this run created
		return fmt.Errorf("salvage %s: %w", opts.Dir, err)
	}
	if err := os.Rename(opts.Dir, kept); err != nil {
		_ = os.RemoveAll(target)
		return fmt.Errorf("keep the damaged journal as %s: %w", kept, err)
	}
	if err := os.Rename(target, opts.Dir); err != nil {
		if back := os.Rename(kept, opts.Dir); back != nil {
			return fmt.Errorf("install the salvaged journal: %w (and restoring %s failed: %v)", err, kept, back)
		}
		return fmt.Errorf("install the salvaged journal: %w (the damaged journal is back in place)", err)
	}
	record := struct {
		At        time.Time `json:"at"`
		Reason    string    `json:"reason"`
		OpenError string    `json:"open_error"`
		Kept      string    `json:"kept"`
		evidence.SalvageReport
	}{time.Now().UTC(), reason, openErr.Error(), kept, report}
	b, _ := json.MarshalIndent(record, "", "  ")
	reportPath := filepath.Join(filepath.Dir(opts.Dir), "evidence-salvage-"+stamp+".json")
	if err := os.WriteFile(reportPath, b, 0o600); err != nil {
		fmt.Fprintf(out, "warning: could not write %s: %v\n", reportPath, err)
	}

	fmt.Fprintf(out, "salvaged %s: %d event(s) kept for delivery, %d already delivered, %d unreadable region(s) (%d bytes), %d cursor(s) carried\n",
		opts.Dir, report.Imported, report.Delivered, report.UnreadableRegions, report.UnreadableBytes, report.Cursors)
	if !report.CheckpointUsable {
		fmt.Fprintln(out, "the delivery state was unreadable: delivered events will be sent again and answered as duplicates")
	}
	if report.UnreadableRegions > 0 {
		fmt.Fprintln(out, "evidence in the unreadable regions is lost; it is counted as unknown gaps in the agent's health")
	}
	for _, p := range report.Problems {
		fmt.Fprintf(out, "  %s\n", p)
	}
	fmt.Fprintf(out, "the damaged journal is kept unchanged at %s; report: %s\nstart the agent again\n", kept, reportPath)
	return nil
}
