//go:build windows

package etw

import (
	"golang.org/x/sys/windows"
)

// Win32 ETW structures, laid out as on 64-bit Windows (abi_windows_test.go
// checks every size and the offsets the code relies on).

// wnodeHeader is WNODE_HEADER.
type wnodeHeader struct {
	BufferSize        uint32
	ProviderID        uint32
	HistoricalContext uint64
	TimeStamp         int64
	GUID              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

// eventTraceProperties is EVENT_TRACE_PROPERTIES; the session name follows it
// in the same allocation (LoggerNameOffset).
type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      windows.Handle
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// eventTraceLogfile is EVENT_TRACE_LOGFILEW. The embedded EVENT_TRACE and
// TRACE_LOGFILE_HEADER are not read by this package, only sized.
type eventTraceLogfile struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        [88]byte
	LogfileHeader       [280]byte
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	Context             uintptr
}

// eventDescriptor is EVENT_DESCRIPTOR.
type eventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

// eventHeader is EVENT_HEADER.
type eventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadID        uint32
	ProcessID       uint32
	TimeStamp       int64
	ProviderID      windows.GUID
	EventDescriptor eventDescriptor
	ProcessorTime   uint64
	ActivityID      windows.GUID
}

// eventRecord is EVENT_RECORD.
type eventRecord struct {
	EventHeader       eventHeader
	BufferContext     uint32 // ETW_BUFFER_CONTEXT
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          uintptr
	UserContext       uintptr
}

// traceEventInfo is the fixed part of TRACE_EVENT_INFO; EVENT_PROPERTY_INFO
// entries follow it.
type traceEventInfo struct {
	ProviderGUID          windows.GUID
	EventGUID             windows.GUID
	EventDescriptor       eventDescriptor
	DecodingSource        uint32
	ProviderNameOffset    uint32
	LevelNameOffset       uint32
	ChannelNameOffset     uint32
	KeywordsNameOffset    uint32
	TaskNameOffset        uint32
	OpcodeNameOffset      uint32
	EventMessageOffset    uint32
	ProviderMessageOffset uint32
	BinaryXMLOffset       uint32
	BinaryXMLSize         uint32
	EventNameOffset       uint32
	EventAttributesOffset uint32
	PropertyCount         uint32
	TopLevelPropertyCount uint32
	Flags                 uint32
}

// eventPropertyInfo is EVENT_PROPERTY_INFO (non-struct variant: InType,
// OutType, MapNameOffset; Count and Length or the indexes they refer to).
type eventPropertyInfo struct {
	Flags         uint32
	NameOffset    uint32
	InType        uint16
	OutType       uint16
	MapNameOffset uint32
	Count         uint16
	Length        uint16
	Reserved      uint32
}

const (
	wnodeFlagTracedGUID = 0x00020000

	eventTraceRealTimeMode     = 0x00000100
	eventTraceSystemLoggerMode = 0x02000000

	processTraceModeRealTime    = 0x00000100
	processTraceModeEventRecord = 0x10000000

	eventTraceControlStop = 1

	eventControlCodeEnableProvider = 1

	propertyStruct      = 0x1
	propertyParamLength = 0x2
	propertyParamCount  = 0x4

	eventHeaderFlag32BitHeader = 0x0020

	errorAlreadyExists        = windows.Errno(183)
	errorInsufficientBuffer   = windows.Errno(122)
	errorWMIInstanceNotFound  = windows.Errno(4201)
	invalidProcessTraceHandle = ^uint64(0)
)

var (
	advapi32                   = windows.NewLazySystemDLL("advapi32.dll")
	tdh                        = windows.NewLazySystemDLL("tdh.dll")
	procStartTraceW            = advapi32.NewProc("StartTraceW")
	procControlTraceW          = advapi32.NewProc("ControlTraceW")
	procEnableTraceEx2         = advapi32.NewProc("EnableTraceEx2")
	procOpenTraceW             = advapi32.NewProc("OpenTraceW")
	procProcessTrace           = advapi32.NewProc("ProcessTrace")
	procCloseTrace             = advapi32.NewProc("CloseTrace")
	procTdhGetEventInformation = tdh.NewProc("TdhGetEventInformation")
	procTdhFormatProperty      = tdh.NewProc("TdhFormatProperty")
)

// systemTraceControlGUID enables kernel events (process, thread, image...)
// in a session started with EVENT_TRACE_SYSTEM_LOGGER_MODE.
var systemTraceControlGUID = windows.GUID{Data1: 0x9e814aad, Data2: 0x3204, Data3: 0x11d2,
	Data4: [8]byte{0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39}}
