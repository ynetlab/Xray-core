package router

import (
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

var _ routing.VlessRouteProvider = (*Router)(nil)

func (r *Router) WithVlessRouteSnapshot(use func(*routing.VlessRouteSnapshot)) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	use(r.vlessRoutes)
}

// publishVlessRoutes is called under the same write lock as rules.Store.
func (r *Router) publishVlessRoutes(rules []*Rule) {
	var present [65536]bool
	if r.script == nil {
		for _, rule := range rules {
			for _, interval := range rule.vlessRoutes {
				for value := uint32(interval.From); value <= uint32(interval.To); value++ {
					present[value] = true
				}
			}
		}
	}
	var routes []net.Port
	for value, found := range present {
		if found {
			routes = append(routes, net.Port(value))
		}
	}
	r.vlessRoutes = routing.NewVlessRouteSnapshot(r.vlessRoutes.Version()+1, routes)
}
