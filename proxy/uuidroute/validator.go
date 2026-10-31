// Package uuidroute indexes UUID password variants while preserving the
// protocol's existing password hash and one logical user per normalized UUID.
package uuidroute

import (
	"maps"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
)

type Match struct {
	User  *protocol.MemoryUser
	Route net.Port
}

type userRecord struct {
	user     *protocol.MemoryUser
	password string
}

type Credential struct {
	User     *protocol.MemoryUser
	Password string
}

// authIndex and all its maps are immutable after a single atomic publication.
type authIndex struct {
	routes      *routing.VlessRouteSnapshot
	userVersion uint64
	hashes      map[string]Match
	userHashes  map[string][]string
}

type Validator struct {
	router   routing.Router
	hash     func(string) string
	emailKey func(string) string
	mu       sync.RWMutex
	users    map[string]userRecord
	emails   map[string]string
	version  uint64
	index    atomic.Pointer[authIndex]
}

// hash must be deterministic and must not re-enter the router or validator.
// User/account values passed to Add are immutable, owned by the caller protocol.
func NewValidator(router routing.Router, hash func(string) string, emailKey func(string) string) *Validator {
	return &Validator{router: router, hash: hash, emailKey: emailKey, users: make(map[string]userRecord), emails: make(map[string]string)}
}

func identity(password string) string {
	if id, err := uuid.Parse(password); err == nil {
		id[6], id[7] = 0, 0
		return id.String()
	}
	return password
}

func (v *Validator) build(users map[string]userRecord, snapshot *routing.VlessRouteSnapshot, version uint64) (*authIndex, error) {
	next := &authIndex{routes: snapshot, userVersion: version, hashes: make(map[string]Match), userHashes: make(map[string][]string, len(users))}
	routes := snapshot.Routes()
	for key, record := range users {
		add := func(password string, route net.Port) error {
			hash := v.hash(password)
			if previous, exists := next.hashes[hash]; exists {
				if previous.User != record.user || previous.Route != route {
					return errors.New("UUID route authentication hash conflicts with another credential")
				}
				return nil
			}
			next.hashes[hash] = Match{User: record.user, Route: route}
			next.userHashes[key] = append(next.userHashes[key], hash)
			return nil
		}
		id, err := uuid.Parse(record.password)
		if err != nil {
			if err := add(record.password, 0); err != nil {
				return nil, err
			}
			continue
		}
		if err := add(record.password, net.PortFromBytes(id[6:8])); err != nil {
			return nil, err
		}
		id[6], id[7] = 0, 0
		if err := add(id.String(), 0); err != nil {
			return nil, err
		}
		for _, route := range routes {
			id[6], id[7] = byte(route>>8), byte(route)
			if err := add(id.String(), route); err != nil {
				return nil, err
			}
		}
	}
	return next, nil
}

// Add serializes user mutations with complete index rebuilds. Routing is always
// leased before mu, including on authentication, so there is no inverse lock order.
func (v *Validator) Add(user *protocol.MemoryUser, password string, replace bool) error {
	return v.AddUsers([]Credential{{User: user, Password: password}}, replace)
}

// AddUsers builds a single index for initial configuration as well as batched
// updates, avoiding a complete rebuild for each individual startup user.
func (v *Validator) AddUsers(credentials []Credential, replace bool) (err error) {
	routing.WithVlessRouteSnapshot(v.router, func(snapshot *routing.VlessRouteSnapshot) {
		v.mu.Lock()
		defer v.mu.Unlock()
		nextUsers, nextEmails := maps.Clone(v.users), maps.Clone(v.emails)
		for _, credential := range credentials {
			user, password := credential.User, credential.Password
			if user == nil {
				err = errors.New("invalid UUID route user")
				return
			}
			key, email := identity(password), v.emailKey(user.Email)
			if previous, found := nextUsers[key]; found && v.emailKey(previous.user.Email) != email {
				err = errors.New("user identity already exists with a different email")
				return
			}
			previousKey, emailExists := nextEmails[email]
			_, identityExists := nextUsers[key]
			if !replace && ((email != "" && emailExists) || identityExists) {
				err = errors.New("User ", user.Email, " already exists.")
				return
			}
			if email != "" && emailExists {
				delete(nextUsers, previousKey)
			}
			nextUsers[key] = userRecord{user: user, password: password}
			if email != "" {
				nextEmails[email] = key
			}
		}
		var next *authIndex
		next, err = v.build(nextUsers, snapshot, v.version+1)
		if err != nil {
			return
		}
		v.users, v.emails = nextUsers, nextEmails
		v.version++
		v.index.Store(next)
	})
	return
}

func (v *Validator) Remove(email string) (removed bool, err error) {
	routing.WithVlessRouteSnapshot(v.router, func(snapshot *routing.VlessRouteSnapshot) {
		v.mu.Lock()
		defer v.mu.Unlock()
		email = v.emailKey(email)
		key, exists := v.emails[email]
		if !exists {
			return
		}
		nextUsers, nextEmails := maps.Clone(v.users), maps.Clone(v.emails)
		delete(nextUsers, key)
		delete(nextEmails, email)
		var next *authIndex
		next, err = v.build(nextUsers, snapshot, v.version+1)
		if err != nil {
			return
		}
		v.users, v.emails = nextUsers, nextEmails
		v.version++
		v.index.Store(next)
		removed = true
	})
	return
}

// Authenticate never uses an index built for a different routing snapshot. The
// lease covers validation, full rebuild, atomic replacement AND hash lookup;
// checking a version and then publishing without this lease would have a race.
func (v *Validator) Authenticate(hash string) (result Match) {
	routing.WithVlessRouteSnapshot(v.router, func(snapshot *routing.VlessRouteSnapshot) {
		current := v.index.Load()
		if current == nil || current.routes != snapshot {
			v.mu.Lock()
			current = v.index.Load()
			if current == nil || current.routes != snapshot {
				next, err := v.build(v.users, snapshot, v.version)
				if err != nil {
					v.mu.Unlock()
					return // Reject instead of authenticating against an obsolete index.
				}
				v.index.Store(next)
				current = next
			}
			v.mu.Unlock()
		}
		result = current.hashes[hash]
	})
	return
}

func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	v.mu.RLock()
	defer v.mu.RUnlock()
	key, exists := v.emails[v.emailKey(email)]
	if !exists {
		return nil
	}
	return v.users[key].user
}

func (v *Validator) GetAll() []*protocol.MemoryUser {
	v.mu.RLock()
	defer v.mu.RUnlock()
	users := make([]*protocol.MemoryUser, 0, len(v.users))
	for _, record := range v.users {
		users = append(users, record.user)
	}
	return users
}

func (v *Validator) GetCount() int64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return int64(len(v.users))
}
