package ie_test

import (
	"errors"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
)

func TestGroupedLookup(t *testing.T) {
	// Keep the process-wide override from leaking into other tests.
	t.Cleanup(func() { ie.SetIsGroupedFun(nil) })

	if !ie.New(ie.CreatePDR, nil).IsGrouped() {
		t.Fatal("CreatePDR is not in the default grouped set")
	}
	if ie.New(ie.Cause, nil).IsGrouped() {
		t.Fatal("Cause is in the default grouped set")
	}

	const vendor = ie.IEType(0x7000)
	ie.AddGroupedIEType(vendor)
	if !ie.New(vendor, nil).IsGrouped() {
		t.Fatal("AddGroupedIEType did not update the default set")
	}

	ie.SetIsGroupedFun(func(ie.IEType) bool { return true })
	if !ie.New(ie.Cause, nil).IsGrouped() {
		t.Fatal("the custom grouped function was not used")
	}

	ie.SetIsGroupedFun(nil)
	if ie.New(ie.Cause, nil).IsGrouped() {
		t.Fatal("a nil grouped function did not restore the default set")
	}
	if !ie.New(vendor, nil).IsGrouped() {
		t.Fatal("restoring the default set lost an added type")
	}
}

func TestParseMultiIEsUsesWireLength(t *testing.T) {
	vendor := ie.NewVendorSpecificIE(0x8001, 0x1234, []byte{1, 2, 3})
	grouped := ie.NewGroupedIE(ie.CreatePDR, ie.New(ie.Cause, nil))
	var wire []byte
	for _, i := range []*ie.IE{vendor, grouped, ie.New(ie.Cause, nil)} {
		b, err := i.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		wire = append(wire, b...)
	}

	got, err := ie.ParseMultiIEs(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("parsed %d IEs, want 3", len(got))
	}
	if got[0].Type != 0x8001 || len(got[0].ChildIEs) != 0 {
		t.Errorf("vendor IE parsed as %+v", got[0])
	}
	if len(got[1].ChildIEs) != 1 || got[1].ChildIEs[0].Type != ie.Cause {
		t.Errorf("grouped IE parsed as %+v", got[1])
	}
	if got[2].Type != ie.Cause {
		t.Errorf("last IE is type %s, want Cause", got[2].Type)
	}
}

func TestParseRejectsExcessiveIEs(t *testing.T) {
	// A zero-length Cause IE is four bytes; one more than the budget is
	// enough to exercise the counter without building a 64 KiB message.
	wire := make([]byte, 4*(4096+1))
	for n := 0; n < 4096+1; n++ {
		wire[4*n] = 0
		wire[4*n+1] = byte(ie.Cause)
	}
	if _, err := ie.ParseMultiIEs(wire); !errors.Is(err, ie.ErrTooManyIEs) {
		t.Fatalf("parsed an oversized IE list with error %v, want ErrTooManyIEs", err)
	}
}

func TestParseRejectsDeepGrouping(t *testing.T) {
	inner := ie.New(ie.Cause, nil)
	for n := 0; n < 17; n++ {
		inner = ie.NewGroupedIE(ie.CreatePDR, inner)
	}
	wire, err := inner.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ie.Parse(wire); !errors.Is(err, ie.ErrTooDeep) {
		t.Fatalf("parsed a deeply nested IE with error %v, want ErrTooDeep", err)
	}
}
