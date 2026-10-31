package routing

import (
	"slices"

	"github.com/xtls/xray-core/common/net"
)

// VlessRouteSnapshot is an immutable set of configured UUID route values.
// A provider must increase the version whenever it publishes new routing rules.
type VlessRouteSnapshot struct {
	version uint64
	routes  []net.Port
}

func NewVlessRouteSnapshot(version uint64, routes []net.Port) *VlessRouteSnapshot {
	routes = slices.Clone(routes)
	slices.Sort(routes)
	return &VlessRouteSnapshot{version: version, routes: slices.Compact(routes)}
}

func (s *VlessRouteSnapshot) Version() uint64 {
	if s == nil {
		return 0
	}
	return s.version
}

// Routes returns a copy; callers cannot mutate a published snapshot.
func (s *VlessRouteSnapshot) Routes() []net.Port {
	if s == nil {
		return nil
	}
	return slices.Clone(s.routes)
}

// VlessRouteProvider optionally extends Router. The callback runs synchronously,
// exactly once, under a routing read lock. Rule publication cannot race with
// authentication index publication or lookup inside the callback. Callbacks
// must not change routing rules, retain locks, or re-enter this provider.
// Consumers that also lock users must always acquire this routing lease first.
type VlessRouteProvider interface {
	WithVlessRouteSnapshot(func(*VlessRouteSnapshot))
}

// WithVlessRouteSnapshot also supports routers without this optional feature:
// only original passwords and normalized base UUIDs are then authenticated.
func WithVlessRouteSnapshot(router Router, use func(*VlessRouteSnapshot)) {
	if provider, ok := router.(VlessRouteProvider); ok {
		provider.WithVlessRouteSnapshot(use)
		return
	}
	use(nil)
}
