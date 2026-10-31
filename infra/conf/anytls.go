package conf

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/anytls"
	"google.golang.org/protobuf/proto"
)

type AnyTLSUser struct {
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

type AnyTLSServerConfig struct {
	Users         []*AnyTLSUser            `json:"users"`
	PaddingScheme []string                 `json:"paddingScheme"`
	Fallbacks     []*TrojanInboundFallback `json:"fallbacks"`
}

func (c *AnyTLSServerConfig) Build() (proto.Message, error) {
	cfg := &anytls.ServerConfig{
		Users: make([]*protocol.User, 0, len(c.Users)),
	}
	if len(c.PaddingScheme) > 0 {
		cfg.PaddingScheme = strings.Join(c.PaddingScheme, "\n")
	}
	for _, fb := range c.Fallbacks {
		if fb == nil || fb.Name != "" || fb.Path != "" || fb.Xver != 0 {
			return nil, errors.New("ANYTLS: fallbacks support dest, type and alpn only")
		}
		var dest string
		var port uint16
		if err := json.Unmarshal(fb.Dest, &port); err == nil && port != 0 {
			dest = strconv.Itoa(int(port))
		} else if err := json.Unmarshal(fb.Dest, &dest); err != nil || dest == "" {
			return nil, errors.New("ANYTLS: fallback dest must be a port or address")
		}
		cfg.Fallbacks = append(cfg.Fallbacks, &anytls.Fallback{Alpn: fb.Alpn, Type: fb.Type, Dest: dest})
	}
	if err := anytls.ValidateFallbacks(cfg.Fallbacks); err != nil {
		return nil, err
	}
	for _, u := range c.Users {
		if u.Password == "" {
			return nil, errors.New("ANYTLS: user password required")
		}
		cfg.Users = append(cfg.Users, &protocol.User{
			Level: uint32(u.Level),
			Email: u.Email,
			Account: serial.ToTypedMessage(&anytls.Account{
				Password: u.Password,
			}),
		})
	}
	return cfg, nil
}

type AnyTLSClientConfig struct {
	Address                  *Address `json:"address"`
	Port                     uint16   `json:"port"`
	Email                    string   `json:"email"`
	Password                 string   `json:"password"`
	Level                    uint32   `json:"level"`
	IdleSessionCheckInterval uint32   `json:"idleSessionCheckInterval"`
	IdleSessionTimeout       uint32   `json:"idleSessionTimeout"`
	MinIdleSession           int      `json:"minIdleSession"`
}

func (c *AnyTLSClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New("ANYTLS: server address is required")
	}
	if c.Password == "" {
		return nil, errors.New("ANYTLS: password is required")
	}

	cfg := &anytls.ClientConfig{
		Server: &protocol.ServerEndpoint{
			Address: c.Address.Build(),
			Port:    uint32(c.Port),
			User: &protocol.User{
				Level: c.Level,
				Email: c.Email,
				Account: serial.ToTypedMessage(&anytls.Account{
					Password: c.Password,
				}),
			},
		},
		IdleSessionCheckInterval: c.IdleSessionCheckInterval,
		IdleSessionTimeout:       c.IdleSessionTimeout,
	}
	if c.MinIdleSession < 0 {
		return nil, errors.New("ANYTLS: minIdleSession must be non-negative")
	}
	cfg.MinIdleSession = uint32(c.MinIdleSession)

	return cfg, nil
}
