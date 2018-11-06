package ztpv4

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

func TestParseV4VendorClass(t *testing.T) {
	tt := []struct {
		name         string
		vc, hostname string
		want         VendorData
		fail         bool
	}{
		{name: "empty", fail: true},
		{name: "unknownVendor", vc: "VendorX;BFR10K;XX12345", fail: true},
		{name: "truncatedVendor", vc: "Arista;1234", fail: true},
		{
			name: "arista",
			vc:   "Arista;DCS-7050S-64;01.23;JPE12345678",
			want: VendorData{
				VendorName: "Arista", Model: "DCS-7050S-64", Serial: "JPE12345678"},
		},
		{
			name: "juniper",
			vc:   "Juniper-ptx1000-DD123",
			want: VendorData{VendorName: "Juniper", Model: "ptx1000", Serial: "DD123"},
		},
		{
			name: "juniperModelDash",
			vc:   "Juniper-qfx10002-36q-DN817",
			want: VendorData{VendorName: "Juniper", Model: "qfx10002-36q", Serial: "DN817"},
		},
		{
			name:     "juniperHostnameSerial",
			vc:       "Juniper-qfx10008",
			hostname: "DE123",
			want:     VendorData{VendorName: "Juniper", Model: "qfx10008", Serial: "DE123"},
		},
		{
			name: "juniperNoSerial",
			vc:   "Juniper-qfx10008",
			want: VendorData{VendorName: "Juniper", Model: "qfx10008", Serial: ""},
		},
		{
			name: "juniperInvalid",
			vc:   "Juniper-",
			want: VendorData{VendorName: "Juniper", Model: "", Serial: ""},
		},
		{
			name: "juniperInvalid2",
			vc:   "Juniper-qfx99999-",
			want: VendorData{VendorName: "Juniper", Model: "qfx99999", Serial: ""},
		},
		{
			name: "zpe",
			vc:   "ZPESystems:NSC:001234567",
			want: VendorData{VendorName: "ZPESystems", Model: "NSC", Serial: "001234567"},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			packet, err := dhcpv4.New()
			if err != nil {
				t.Fatalf("failed to creat dhcpv4 packet object: %v", err)
			}

			packet.AddOption(&dhcpv4.OptClassIdentifier{
				Identifier: tc.vc,
			})

			if tc.hostname != "" {
				packet.AddOption(&dhcpv4.OptHostName{
					HostName: tc.hostname,
				})
			}

			vd := VendorData{}

			if err := parseV4VendorClass(&vd, packet); err != nil && !tc.fail {
				t.Errorf("unexpected failure: %v", err)
			}

			if !cmp.Equal(tc.want, vd) {
				t.Errorf("unexpected VendorData:\n%s", cmp.Diff(tc.want, vd))
			}
		})
	}
}

func TestParseV4VIVC(t *testing.T) {
	tt := []struct {
		name  string
		entID uint32
		input []byte
		want  VendorData
		fail  bool
	}{
		{name: "empty", fail: true},
		{
			name:  "ciscoIOSXR",
			entID: 0x09,
			input: []byte("SN:0;PID:R-IOSXRV9000-CC"),
			want:  VendorData{VendorName: "Cisco Systems", Model: "R-IOSXRV9000-CC", Serial: "0"},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			packet, err := dhcpv4.New()
			if err != nil {
				t.Fatalf("failed to creat dhcpv4 packet object: %v", err)
			}
			packet.AddOption(&dhcpv4.OptVIVC{
				Identifiers: []dhcpv4.VIVCIdentifier{
					{EntID: tc.entID, Data: tc.input},
				},
			})

			vd := VendorData{}

			if err := parseV4VIVC(&vd, packet); err != nil && !tc.fail {
				t.Errorf("unexpected failure: %v", err)
			}

			if !cmp.Equal(tc.want, vd) {
				t.Errorf("unexpected VendorData:\n%s", cmp.Diff(tc.want, vd))
			}
		})
	}
}
