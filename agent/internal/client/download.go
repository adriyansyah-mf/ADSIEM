package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DownloadAttempts is how many connections Download opens for one file.
const DownloadAttempts = 6

// downloadBackoff is the pause before reconnect n (tests shorten it).
var downloadBackoff = func(n int) time.Duration { return time.Duration(n) * 2 * time.Second }

// Download copies path into w, resuming where a broken connection left off.
// A slow or lossy link (an endpoint on a mobile network, a server with a
// congested uplink) drops large transfers part way; starting over each time
// may never finish. After a drop it asks for the rest (Range: bytes=N-) and
// carries on when the server answers 206 from byte N. A server that answers
// 200 again would resend from the start, which w (a hashing, size-limited
// writer) cannot take back: that ends the download with the error.
func (c *Client) Download(ctx context.Context, path string, w io.Writer) error {
	var done int64
	var lastErr error
	for attempt := 0; attempt < DownloadAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(downloadBackoff(attempt)):
			}
		}
		n, retry, err := c.downloadFrom(ctx, path, w, done)
		done += n
		if err == nil {
			return nil
		}
		lastErr = err
		if !retry || ctx.Err() != nil {
			break
		}
	}
	if done > 0 {
		return fmt.Errorf("after %d bytes: %w", done, lastErr)
	}
	return lastErr
}

// downloadFrom copies from offset on: n bytes written, retry when a new
// connection may get the rest.
func (c *Client) downloadFrom(ctx context.Context, path string, w io.Writer, offset int64) (n int64, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+path, nil)
	if err != nil {
		return 0, false, fmt.Errorf("new request: %w", err)
	}
	c.setToken(req)
	if offset > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(offset, 10)+"-")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, true, err // no connection: try again
	}
	defer resp.Body.Close()
	switch {
	case offset == 0 && resp.StatusCode == http.StatusOK:
	case offset > 0 && resp.StatusCode == http.StatusPartialContent:
		if start, ok := rangeStart(resp.Header.Get("Content-Range")); !ok || start != offset {
			return 0, false, fmt.Errorf("server resumed at %q, not byte %d", resp.Header.Get("Content-Range"), offset)
		}
	case offset > 0 && resp.StatusCode == http.StatusOK:
		return 0, false, errors.New("server cannot resume a download (answered 200 to a range request)")
	default:
		return 0, resp.StatusCode >= 500, fmt.Errorf("server answered %s", resp.Status)
	}
	n, err = io.Copy(w, resp.Body)
	if err != nil {
		var we *writeError
		if errors.As(err, &we) {
			return n, false, we.err // the writer refused: not a network problem
		}
		return n, true, err
	}
	return n, false, nil
}

// rangeStart reads N of "bytes N-M/T".
func rangeStart(cr string) (int64, bool) {
	cr = strings.TrimSpace(cr)
	if !strings.HasPrefix(cr, "bytes ") {
		return 0, false
	}
	dash := strings.IndexByte(cr, '-')
	if dash < 0 {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(cr[len("bytes "):dash]), 10, 64)
	return v, err == nil
}

// writeError marks an error of the destination, so a full or failing writer
// is not mistaken for a dropped connection.
type writeError struct{ err error }

func (e *writeError) Error() string { return e.err.Error() }
func (e *writeError) Unwrap() error { return e.err }

// WriterErrors wraps w so its errors end a Download at once instead of
// being retried.
func WriterErrors(w io.Writer) io.Writer { return writerErrors{w} }

type writerErrors struct{ w io.Writer }

func (x writerErrors) Write(p []byte) (int, error) {
	n, err := x.w.Write(p)
	if err != nil {
		return n, &writeError{err}
	}
	return n, nil
}
