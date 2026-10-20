package ie

import (
	"sync"
	"sync/atomic"
)

// defaultGroupedIEMap is the source of the default grouped-type set. It is
// read once at package initialization; the hot lookup uses the immutable
// bitset below.
var defaultGroupedIEMap = map[IEType]bool{
	CreatePDR:                            true,
	PDI:                                  true,
	CreateFAR:                            true,
	ForwardingParameters:                 true,
	DuplicatingParameters:                true,
	CreateURR:                            true,
	CreateQER:                            true,
	CreatedPDR:                           true,
	UpdatePDR:                            true,
	UpdateFAR:                            true,
	UpdateForwardingParameters:           true,
	UpdateBARWithinSessionReportResponse: true,
	UpdateURR:                            true,
	UpdateQER:                            true,
	RemovePDR:                            true,
	RemoveFAR:                            true,
	RemoveURR:                            true,
	RemoveQER:                            true,
	LoadControlInformation:               true,
	OverloadControlInformation:           true,
	ApplicationIDsPFDs:                   true,
	PFDContext:                           true,
	ApplicationDetectionInformation:      true,
	QueryURR:                             true,
	UsageReportWithinSessionModificationResponse: true,
	UsageReportWithinSessionDeletionResponse:     true,
	UsageReportWithinSessionReportRequest:        true,
	DownlinkDataReport:                           true,
	CreateBAR:                                    true,
	UpdateBARWithinSessionModificationRequest:    true,
	RemoveBAR:                                                 true,
	ErrorIndicationReport:                                     true,
	UserPlanePathFailureReport:                                true,
	UpdateDuplicatingParameters:                               true,
	AggregatedURRs:                                            true,
	CreateTrafficEndpoint:                                     true,
	CreatedTrafficEndpoint:                                    true,
	UpdateTrafficEndpoint:                                     true,
	RemoveTrafficEndpoint:                                     true,
	EthernetPacketFilter:                                      true,
	EthernetTrafficInformation:                                true,
	AdditionalMonitoringTime:                                  true,
	CreateMAR:                                                 true,
	TGPPAccessForwardingActionInformation:                     true,
	NonTGPPAccessForwardingActionInformation:                  true,
	RemoveMAR:                                                 true,
	UpdateMAR:                                                 true,
	UpdateTGPPAccessForwardingActionInformation:               true,
	UpdateNonTGPPAccessForwardingActionInformation:            true,
	PFCPSessionRetentionInformation:                           true,
	UserPlanePathRecoveryReport:                               true,
	IPMulticastAddressingInfo:                                 true,
	JoinIPMulticastInformationWithinUsageReport:               true,
	LeaveIPMulticastInformationWithinUsageReport:              true,
	CreatedBridgeInfoForTSC:                                   true,
	TSCManagementInformationWithinSessionModificationRequest:  true,
	TSCManagementInformationWithinSessionModificationResponse: true,
	TSCManagementInformationWithinSessionReportRequest:        true,
	ClockDriftControlInformation:                              true,
	ClockDriftReport:                                          true,
	RemoveSRR:                                                 true,
	CreateSRR:                                                 true,
	UpdateSRR:                                                 true,
	SessionReport:                                             true,
	AccessAvailabilityControlInformation:                      true,
	AccessAvailabilityReport:                                  true,
	ProvideATSSSControlInformation:                            true,
	ATSSSControlParameters:                                    true,
	MPTCPParameters:                                           true,
	ATSSSLLParameters:                                         true,
	PMFParameters:                                             true,
	UEIPAddressPoolInformation:                                true,
	GTPUPathQoSControlInformation:                             true,
	GTPUPathQoSReport:                                         true,
	QoSInformationInGTPUPathQoSReport:                         true,
	QoSMonitoringPerQoSFlowControlInformation:                 true,
	QoSMonitoringReport:                                       true,
	PacketRateStatusReport:                                    true,
	EthernetContextInformation:                                true,
	RedundantTransmissionParameters:                           true,
	UpdatedPDR:                                                true,
	ProvideRDSConfigurationInformation:                        true,
	QueryPacketRateStatusWithinSessionModificationRequest:     true,
	PacketRateStatusReportWithinSessionModificationResponse:   true,
	UEIPAddressUsageInformation:                               true,
	RedundantTransmissionForwardingParameters:                 true,
	TransportDelayReporting:                                   true,
}

// groupedTable is an immutable 65,536-bit set of IE types. A reader does one
// atomic load and a bit test; AddGroupedIEType copies the table under a mutex
// and publishes the copy. The default lookup used to take a shared RWMutex and
// probe a map for every IE, which cost more than the rest of a short IE parse.
type groupedTable struct {
	bits [1 << 10]uint64
}

func newGroupedTable(types map[IEType]bool) *groupedTable {
	t := &groupedTable{}
	for typ := range types {
		t.add(typ)
	}
	return t
}

func (t *groupedTable) add(typ IEType) {
	v := uint16(typ)
	t.bits[v>>6] |= 1 << (v & 63)
}

func (t *groupedTable) has(typ IEType) bool {
	v := uint16(typ)
	return t.bits[v>>6]&(1<<(v&63)) != 0
}

func (t *groupedTable) with(types ...IEType) *groupedTable {
	next := *t
	for _, typ := range types {
		next.add(typ)
	}
	return &next
}

type groupedFunc struct {
	fn func(IEType) bool
}

var (
	addGroupedMu    sync.Mutex
	defaultGrouped  atomic.Pointer[groupedTable]
	customGroupedFn atomic.Pointer[groupedFunc]
)

func init() {
	defaultGrouped.Store(newGroupedTable(defaultGroupedIEMap))
}

// SetIsGroupedFun sets a function to check if an IE is grouped type or not.
// A nil function restores the default table. The function is read with one
// atomic load, so callers may set it while parsers run.
func SetIsGroupedFun(fun func(t IEType) bool) {
	if fun == nil {
		customGroupedFn.Store(nil)
		return
	}
	customGroupedFn.Store(&groupedFunc{fn: fun})
}

// AddGroupedIEType adds IE type(s) to the default grouped-type set.
// This is useful when you want to handle vendor-specific IEs as grouped types.
// The update copies the bitset; it is not on the packet-parse path.
func AddGroupedIEType(ts ...IEType) {
	addGroupedMu.Lock()
	defer addGroupedMu.Unlock()
	base := defaultGrouped.Load()
	if base == nil {
		base = &groupedTable{}
	}
	defaultGrouped.Store(base.with(ts...))
}

// IsGrouped reports whether an IE is grouped type or not.
//
// By default, this package uses the built-in grouped-type table. You can
// replace that lookup with SetIsGroupedFun(), or extend the table with
// AddGroupedIEType(). The default lookup is lock-free.
func (i *IE) IsGrouped() bool {
	if f := customGroupedFn.Load(); f != nil {
		return f.fn(i.Type)
	}
	return defaultGrouped.Load().has(i.Type)
}

// Add adds variable number of IEs to a IE if the IE is grouped type and update length.
// Otherwise, this does nothing (no errors).
func (i *IE) Add(ies ...*IE) {
	if !i.IsGrouped() {
		return
	}

	i.Payload = nil
	i.ChildIEs = append(i.ChildIEs, ies...)
	for _, ie := range i.ChildIEs {
		serialized, err := ie.Marshal()
		if err != nil {
			continue
		}
		i.Payload = append(i.Payload, serialized...)
	}
	i.SetLength()
}

// Remove removes an IE looked up by type.
func (i *IE) Remove(typ IEType) {
	if !i.IsGrouped() {
		return
	}

	i.Payload = nil
	newChildren := make([]*IE, len(i.ChildIEs))
	idx := 0
	for _, ie := range i.ChildIEs {
		if ie.Type == typ {
			newChildren = newChildren[:len(newChildren)-1]
			continue
		}
		newChildren[idx] = ie
		idx++

		serialized, err := ie.Marshal()
		if err != nil {
			continue
		}
		i.Payload = append(i.Payload, serialized...)
	}
	i.ChildIEs = newChildren
	i.SetLength()
}

// FindByType returns IE looked up by type.
//
// The program may be slower when calling this method multiple times
// because this ranges over a ChildIEs each time it is called.
func (i *IE) FindByType(typ IEType) (*IE, error) {
	if !i.IsGrouped() {
		return nil, ErrInvalidType
	}

	for _, ie := range i.ChildIEs {
		if ie.Type == typ {
			return ie, nil
		}
	}
	return nil, ErrIENotFound
}
