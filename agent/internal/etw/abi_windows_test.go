//go:build windows

package etw

import (
	"testing"
	"unsafe"
)

// The sizes and offsets of the 64-bit Win32 structures: a wrong one makes
// Windows read or write the wrong memory.
func TestABILayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("layouts are for 64-bit Windows")
	}
	var lf eventTraceLogfile
	var p eventTraceProperties
	var r eventRecord
	var etp enableTraceParameters
	for name, c := range map[string]struct{ got, want uintptr }{
		"ENABLE_TRACE_PARAMETERS":                  {unsafe.Sizeof(etp), 48},
		"ENABLE_TRACE_PARAMETERS.EnableFilterDesc": {unsafe.Offsetof(etp.EnableFilterDesc), 32},
		"ENABLE_TRACE_PARAMETERS.FilterDescCount":  {unsafe.Offsetof(etp.FilterDescCount), 40},
		"EVENT_FILTER_DESCRIPTOR":                  {unsafe.Sizeof(eventFilterDescriptor{}), 16},
		"WNODE_HEADER":                             {unsafe.Sizeof(wnodeHeader{}), 48},
		"EVENT_TRACE_PROPERTIES":                   {unsafe.Sizeof(p), 120},
		"EVENT_TRACE_PROPERTIES.LoggerThreadId":    {unsafe.Offsetof(p.LoggerThreadID), 104},
		"EVENT_TRACE_PROPERTIES.LoggerNameOffset":  {unsafe.Offsetof(p.LoggerNameOffset), 116},
		"EVENT_TRACE_LOGFILEW":                     {unsafe.Sizeof(lf), 448},
		"EVENT_TRACE_LOGFILEW.ProcessTraceMode":    {unsafe.Offsetof(lf.ProcessTraceMode), 28},
		"EVENT_TRACE_LOGFILEW.BufferCallback":      {unsafe.Offsetof(lf.BufferCallback), 400},
		"EVENT_TRACE_LOGFILEW.EventRecordCallback": {unsafe.Offsetof(lf.EventRecordCallback), 424},
		"EVENT_TRACE_LOGFILEW.Context":             {unsafe.Offsetof(lf.Context), 440},
		"EVENT_DESCRIPTOR":                         {unsafe.Sizeof(eventDescriptor{}), 16},
		"EVENT_HEADER":                             {unsafe.Sizeof(eventHeader{}), 80},
		"EVENT_RECORD":                             {unsafe.Sizeof(r), 112},
		"EVENT_RECORD.UserDataLength":              {unsafe.Offsetof(r.UserDataLength), 86},
		"EVENT_RECORD.UserData":                    {unsafe.Offsetof(r.UserData), 96},
		"EVENT_RECORD.UserContext":                 {unsafe.Offsetof(r.UserContext), 104},
		"TRACE_EVENT_INFO (fixed part)":            {unsafe.Sizeof(traceEventInfo{}), 112},
		"EVENT_PROPERTY_INFO":                      {unsafe.Sizeof(eventPropertyInfo{}), 24},
	} {
		if c.got != c.want {
			t.Errorf("%s: %d, want %d", name, c.got, c.want)
		}
	}
}
