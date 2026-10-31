package conf_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/anytls"
	"google.golang.org/protobuf/proto"
)

func TestAnyTLSFallbackConfig(t *testing.T) {
	unixConfig, err := json.Marshal(map[string]any{"fallbacks": []map[string]any{{"dest": filepath.Join(t.TempDir(), "backend.sock")}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, config string
		valid        bool
	}{
		{"disabled", `{}`, true},
		{"default-port", `{"fallbacks":[{"dest":8080}]}`, true},
		{"port-string", `{"fallbacks":[{"dest":"8080"}]}`, true},
		{"ALPN", `{"fallbacks":[{"dest":8080},{"alpn":"h2","dest":"[::1]:8081"}]}`, true},
		{"TCP", `{"fallbacks":[{"type":"tcp","dest":"localhost:8080"}]}`, true},
		{"Unix", string(unixConfig), true},
		{"missing", `{"fallbacks":[{}]}`, false},
		{"null", `{"fallbacks":[null]}`, false},
		{"null-dest", `{"fallbacks":[{"dest":null}]}`, false},
		{"zero", `{"fallbacks":[{"dest":0}]}`, false},
		{"negative", `{"fallbacks":[{"dest":-1}]}`, false},
		{"overflow", `{"fallbacks":[{"dest":65536}]}`, false},
		{"object", `{"fallbacks":[{"dest":{"host":"localhost"}}]}`, false},
		{"duplicate", `{"fallbacks":[{"dest":80},{"dest":81}]}`, false},
		{"UDP", `{"fallbacks":[{"type":"udp","dest":80}]}`, false},
		{"SNI-unsupported", `{"fallbacks":[{"name":"example.com","dest":80}]}`, false},
		{"path-unsupported", `{"fallbacks":[{"path":"/x","dest":80}]}`, false},
		{"PROXY-unsupported", `{"fallbacks":[{"xver":1,"dest":80}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var config conf.AnyTLSServerConfig
			if err := json.Unmarshal([]byte(tc.config), &config); err != nil {
				t.Fatal(err)
			}
			built, err := config.Build()
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if err != nil {
				return
			}
			encoded, err := proto.Marshal(built)
			if err != nil {
				t.Fatal(err)
			}
			var decoded anytls.ServerConfig
			if err := proto.Unmarshal(encoded, &decoded); err != nil || !proto.Equal(built, &decoded) {
				t.Fatal("fallback configuration lost in protobuf round trip", err)
			}
		})
	}
}
