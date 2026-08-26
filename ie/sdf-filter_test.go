package ie_test

import (
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/wmnsk/go-pfcp/ie"
)

func TestParseSDFFilterFields(t *testing.T) {
	cases := []struct {
		description string
		serialized  []byte
		structured  *ie.SDFFilterFields
		err         error
	}{
		{
			description: "FlowDescription",
			serialized:  []byte{0x01, 0x00, 0x00, 0x03, 0x66, 0x6f, 0x6f},
			structured: &ie.SDFFilterFields{
				Flags:           0x01,
				FDLength:        3,
				FlowDescription: "foo",
			},
		},
		{
			description: "FDLengthOverrunsBuffer",
			// FD flag set, FDLength=0xfffe but only two payload bytes follow.
			serialized: []byte{0x01, 0x00, 0xff, 0xfe, 0x01, 0x02},
			structured: nil,
			err:        io.ErrUnexpectedEOF,
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			got, err := ie.ParseSDFFilterFields(c.serialized)
			if err != c.err {
				t.Errorf("expected error %v but got %v", c.err, err)
				t.Fatal(err)
			}

			if diff := cmp.Diff(got, c.structured); diff != "" {
				t.Error(diff)
			}
		})
	}
}
