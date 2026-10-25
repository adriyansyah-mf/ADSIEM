// Package winevent reads the Windows Event Log. Format (this file) is
// platform independent so it can be tested anywhere; the subscription lives
// in subscribe_windows.go.
package winevent

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ErrUnsupported is returned by Subscribe on platforms without a Windows Event Log.
var ErrUnsupported = errors.New("Windows Event Log sources (eventlog:...) only work on Windows")

// eventXML is the subset of the Windows event schema the agent ships.
type eventXML struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Level       string `xml:"Level"`
		Task        string `xml:"Task"`
		Opcode      string `xml:"Opcode"`
		Keywords    string `xml:"Keywords"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID string `xml:"EventRecordID"`
		Execution     struct {
			ProcessID string `xml:"ProcessID,attr"`
			ThreadID  string `xml:"ThreadID,attr"`
		} `xml:"Execution"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
		Security struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Inner []byte `xml:",innerxml"`
	} `xml:"UserData"`
}

// FormatXML turns one rendered event (EvtRenderEventXml) into a single
// key=value line the server's kv decoders parse:
//
//	EventID=4625 Channel="Security" Provider="Microsoft-Windows-Security-Auditing" Computer="WIN01" ... TargetUserName="admin" IpAddress="203.0.113.7"
//
// System fields come first in a fixed order, then EventData/UserData fields
// sorted by name. EventData entries without a Name become Data1, Data2, ...
func FormatXML(raw []byte) (string, error) {
	pairs, err := fieldPairs(raw)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("EventID=" + pairs[0].value)
	for _, p := range pairs[1:] {
		b.WriteString(" " + p.key + "=" + quote(p.value))
	}
	return b.String(), nil
}

// Fields returns the same fields FormatXML writes, as a map (live-response
// event log queries emit them as rows).
func Fields(raw []byte) (map[string]string, error) {
	pairs, err := fieldPairs(raw)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		out[p.key] = p.value
	}
	return out, nil
}

type pair struct{ key, value string }

// fieldPairs: EventID first, then System fields in a fixed order, then
// EventData/UserData sorted by name; empty values are left out.
func fieldPairs(raw []byte) ([]pair, error) {
	var ev eventXML
	if err := xml.Unmarshal(raw, &ev); err != nil {
		return nil, fmt.Errorf("parse event xml: %w", err)
	}
	s := ev.System
	if strings.TrimSpace(s.EventID) == "" {
		return nil, fmt.Errorf("event has no EventID")
	}

	pairs := []pair{{"EventID", strings.TrimSpace(s.EventID)}}
	add := func(k, v string) {
		if v = strings.TrimSpace(v); v != "" {
			pairs = append(pairs, pair{k, v})
		}
	}
	add("Channel", s.Channel)
	add("Provider", s.Provider.Name)
	add("Computer", s.Computer)
	add("RecordID", s.EventRecordID)
	add("Level", s.Level)
	add("Task", s.Task)
	add("Opcode", s.Opcode)
	add("Keywords", s.Keywords)
	add("TimeCreated", s.TimeCreated.SystemTime)
	add("ProcessID", s.Execution.ProcessID)
	add("UserSID", s.Security.UserID)

	data := map[string]string{}
	for i, d := range ev.EventData.Data {
		name := safeKey(d.Name)
		if name == "" {
			name = "Data" + strconv.Itoa(i+1)
		}
		data[name] = d.Value
	}
	for k, v := range userDataFields(ev.UserData.Inner) {
		if _, taken := data[k]; !taken {
			data[k] = v
		}
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if isSystemKey(k) {
			add("Data_"+k, data[k]) // never let event data shadow System fields
		} else {
			add(k, data[k])
		}
	}
	return pairs, nil
}

var systemKeys = map[string]bool{
	"EventID": true, "Channel": true, "Provider": true, "Computer": true, "RecordID": true, "Level": true,
	"Task": true, "Opcode": true, "Keywords": true, "TimeCreated": true, "ProcessID": true, "UserSID": true,
}

func isSystemKey(k string) bool { return systemKeys[k] }

// userDataFields flattens <UserData><Something><Field>v</Field>...</Something></UserData>
// (used by e.g. 1102 "log cleared" and many Operational channels) to Field=v.
func userDataFields(inner []byte) map[string]string {
	out := map[string]string{}
	if len(bytes.TrimSpace(inner)) == 0 {
		return out
	}
	dec := xml.NewDecoder(bytes.NewReader(inner))
	var stack []string
	var text strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			text.Reset()
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			// a leaf two or more levels deep: <Wrapper><Field>value</Field></Wrapper>
			if len(stack) >= 2 {
				if v := strings.TrimSpace(text.String()); v != "" {
					if k := safeKey(t.Name.Local); k != "" {
						out[k] = v
					}
				}
			}
			text.Reset()
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	return out
}

// safeKey keeps the key a single \w+ token so the server's kv parser reads it.
// Spaces are dropped ("New Value" → NewValue), the field names Sigma rules use.
func safeKey(k string) string {
	var b strings.Builder
	for _, r := range k {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		case r == '-' || r == '.':
			b.WriteRune('_')
		}
	}
	return b.String()
}

// Quote is quote for other producers of key=value event lines (the ETW sensor).
func Quote(v string) string { return quote(v) }

// quote wraps a value for the kv parser (`key="..."`). A double quote is
// written \" and a backslash is doubled only where it would be ambiguous —
// before another backslash or a quote, or at the end — so Windows paths stay
// readable while the server recovers the exact value (command lines keep
// their quotes, which Sigma rules match on). Line breaks become spaces so a
// script block can't split the event.
func quote(v string) string {
	v = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ", "\t", " ").Replace(v)
	var b strings.Builder
	b.Grow(len(v) + 2)
	b.WriteByte('"')
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\' && (i+1 == len(v) || v[i+1] == '\\' || v[i+1] == '"'):
			b.WriteString(`\\`)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
