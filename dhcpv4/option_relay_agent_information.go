package dhcpv4

import (
	"fmt"
)

// RelayOptions is like Options, but stringifies using the Relay Agent Specific
// option space.
type RelayOptions struct {
	Options
}

var relayHumanizer = OptionHumanizer{
	ValueHumanizer: func(code OptionCode, data []byte) fmt.Stringer {
		return OptionGeneric{data}
	},
	CodeHumanizer: func(c uint8) OptionCode {
		return RAISubOptionCode(c)
	},
}

// String prints the contained options using Relay Agent-specific option code parsing.
func (r RelayOptions) String() string {
	return r.Options.ToString(relayHumanizer)
}

// FromBytes parses relay agent options from data.
func (r *RelayOptions) FromBytes(data []byte) error {
	r.Options = make(Options)
	return r.Options.FromBytes(data)
}

// OptRelayAgentInfo returns a new DHCP Relay Agent Info option.
//
// The relay agent info option is described by RFC 3046.
func OptRelayAgentInfo(o ...Option) Option {
	return Option{Code: OptionRelayAgentInformation, Value: RelayOptions{OptionsFromList(o...)}}
}

// RAISubOptionCode is the code type for Relay Agent Information
type RAISubOptionCode uint8

// Code returns the uint8 value of the RAI (relay agent information) code.
func (o RAISubOptionCode) Code() uint8 {
	return uint8(o)
}

func (o RAISubOptionCode) String() string {
	if s, ok := raiSubOptionCodeToString[o]; ok {
		return fmt.Sprintf("%s (%d)", s, o)
	}
	return fmt.Sprintf("unknown (%d)", o)
}

// Option 82 Relay Agention Information Sub Options
const (
	RAIAgentCircuitID                RAISubOptionCode = 1   // RFC 3046
	RAIAgentRemoteID                 RAISubOptionCode = 2   // RFC 3046
	RAIDOCSISDeviceClass             RAISubOptionCode = 4   // RFC 3256
	RAILinkSelection                 RAISubOptionCode = 5   // RFC 3527
	RAISubscriberID                  RAISubOptionCode = 6   // RFC 3993
	RAIRADIUSAttributes              RAISubOptionCode = 7   // RFC 4014
	RAIAuthentication                RAISubOptionCode = 8   // RFC 4030
	RAIVendorSpecificInformation     RAISubOptionCode = 9   // RFC 4243
	RAIRelayAgentFlags               RAISubOptionCode = 10  // RFC 5010
	RAIServerIdentifierOverride      RAISubOptionCode = 11  // RFC 5107
	RAIVirtualSubnetSelection        RAISubOptionCode = 151 // RFC 6607
	RAIVirtualSubnetSelectionControl RAISubOptionCode = 152 // RFC 6607
)

// raiSubOptionCodeToString is a simple code -> string map for RAI codes.
var raiSubOptionCodeToString = map[RAISubOptionCode]string{
	RAIAgentCircuitID:                "Agent Circuit ID",
	RAIAgentRemoteID:                 "Agent Remote ID",
	RAIDOCSISDeviceClass:             "DOCSIS Device Class",
	RAILinkSelection:                 "Link Selection",
	RAISubscriberID:                  "Subscriber ID",
	RAIRADIUSAttributes:              "RADIUS Attributes",
	RAIAuthentication:                "Authentication",
	RAIVendorSpecificInformation:     "Vendor Specific",
	RAIRelayAgentFlags:               "Relay Agent Flags",
	RAIServerIdentifierOverride:      "Server Identifier Override",
	RAIVirtualSubnetSelection:        "Virtual Subnet Selection",
	RAIVirtualSubnetSelectionControl: "Virtual Subnet Selection Control",
}
