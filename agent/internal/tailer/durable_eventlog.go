package tailer

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/siem-platform/agent/internal/evidence"
	"github.com/siem-platform/agent/internal/winevent"
)

// Tests replace the native calls; production uses wevtapi through winevent.
var (
	subscribeEventLog = winevent.SubscribeResume
	baselineEventLog  = winevent.Baseline
	eventLogRetryMin  = 5 * time.Second
)

const eventLogRetryMax = 5 * time.Minute

// TailEventLogDurable follows a Windows Event Log channel ("eventlog:<name>")
// into the journal through sink. Its cursor (source = path, identity =
// channel) carries the bookmark of the last admitted event, written in the
// same journal record as the event, so a restart resumes strictly after it.
// The first subscription keeps the future-only policy by baselining the
// newest retained event; an empty channel resumes from its oldest event so
// events written while the agent was down are not lost. A cleared or rolled
// over channel is a gap: a new generation starts at the oldest retained event.
func TailEventLogDurable(ctx context.Context, path, logType string, j *evidence.Journal, sink DurableSink) error {
	channel := strings.TrimPrefix(path, EventLogPrefix)
	g := &sourceGuard{ctx: ctx, j: j, health: path, label: path}
	wait := eventLogRetryMin

	cur, ok := j.Cursor(path)
	for !ok {
		r, err := baselineEventLog(ctx, channel)
		if errors.Is(err, winevent.ErrUnsupported) {
			slog.Warn("ignoring event log source on a non-Windows host", "path", path)
			g.setState("unavailable", "unsupported")
			return nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("event log baseline failed, retrying", "channel", channel, "err", err, "retry_in", wait)
			g.setState("unavailable", "baseline_error")
			if !sleepCtx(ctx, wait) {
				return nil
			}
			wait = nextWait(wait)
			continue
		}
		cur = evidence.Cursor{Source: path, Generation: newGeneration(), Identity: channel, Bookmark: r.Bookmark, Empty: r.Empty}
		if err := g.control(func() error { return j.SaveBaseline(ctx, cur) }); err != nil {
			return quiet(ctx, err)
		}
		ok = true
	}

	for {
		resume := winevent.Resume{Bookmark: cur.Bookmark, Empty: cur.Bookmark == "", Initialized: true}
		slog.Info("subscribing to event log durably", "channel", channel, "type", logType, "from_oldest", resume.Empty)
		err := subscribeEventLog(ctx, channel, resume, func(ev winevent.Event) error {
			next := evidence.Cursor{Source: path, Generation: cur.Generation, Identity: channel, Bookmark: ev.Bookmark}
			if err := admitEvent(g, sink, path, logType, ev, next); err != nil {
				return err
			}
			cur, wait = next, eventLogRetryMin
			return nil
		})
		if ctx.Err() != nil {
			return nil
		}
		switch {
		case errors.Is(err, winevent.ErrUnsupported):
			g.setState("unavailable", "unsupported")
			return nil
		case errors.Is(err, winevent.ErrBookmarkGap):
			slog.Warn("event log bookmark no longer retained; recovering from the oldest event", "channel", channel, "err", err)
			if err := g.loss("rotation_gap", 0, true); err != nil {
				return quiet(ctx, err)
			}
			cur = evidence.Cursor{Source: path, Generation: newGeneration(), Identity: channel, Empty: true}
			if err := g.control(func() error { return j.SaveBaseline(ctx, cur) }); err != nil {
				return quiet(ctx, err)
			}
		case errors.Is(err, evidence.ErrPublisherStopped):
			return nil
		default:
			// access denied, a channel that does not exist yet (Sysmon not
			// installed), a failed admission: keep the committed bookmark
			slog.Warn("event log subscription ended, retrying", "channel", channel, "err", err, "retry_in", wait)
			g.setState("unavailable", "subscribe_error")
			if !sleepCtx(ctx, wait) {
				return nil
			}
			wait = nextWait(wait)
		}
	}
}

// admitEvent admits one event with its bookmark, or durably records why it
// could not; either way the bookmark only moves after the journal write.
func admitEvent(g *sourceGuard, sink DurableSink, path, logType string, ev winevent.Event, next evidence.Cursor) error {
	if ev.Err == nil {
		d := evidence.Draft{LogType: logType, Location: path, RawMessage: ev.Line, Cursor: &next}
		err := g.retry(func() error {
			_, err := sink.Submit(g.ctx, d)
			return err
		})
		if !errors.Is(err, evidence.ErrOversize) {
			return err
		}
		slog.Warn("event over the event size limit skipped", "path", path, "record_id", ev.RecordID)
		if err := g.loss("oversize", 1, false); err != nil {
			return err
		}
	} else {
		slog.Warn("event log record could not be rendered", "path", path, "record_id", ev.RecordID, "err", ev.Err)
		if err := g.loss("source_failure", 1, false); err != nil {
			return err
		}
	}
	return g.control(func() error { return g.j.SaveBaseline(g.ctx, next) })
}

func nextWait(d time.Duration) time.Duration {
	if d *= 2; d > eventLogRetryMax {
		return eventLogRetryMax
	}
	return d
}

func quiet(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return nil
	}
	return err
}
