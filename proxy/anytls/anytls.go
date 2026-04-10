package anytls

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

const protocolName = "anytls"

var addrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(0x01, net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(0x04, net.AddressFamilyIPv6),
	protocol.AddressFamilyByte(0x03, net.AddressFamilyDomain),
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
