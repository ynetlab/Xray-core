package anytls

import (
	"context"
	"crypto/sha256"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

// AnyTLS authenticates the SHA-256 of the password, so UUID route variants
// must be indexed before authentication rather than decoded from the wire.
func passwordHashes(password string) (string, map[[32]byte]net.Port) {
	hashes := make(map[[32]byte]net.Port)
	id, err := uuid.Parse(password)
	if err != nil {
		hashes[sha256.Sum256([]byte(password))] = 0
		return password, hashes
	}
	hashes[sha256.Sum256([]byte(password))] = net.PortFromBytes(id[6:8])
	id[6], id[7] = 0, 0
	identity := id.String()
	hashes[sha256.Sum256([]byte(identity))] = 0
	for route := uint16(1001); route <= 1100; route++ {
		id[6], id[7] = byte(route>>8), byte(route)
		hashes[sha256.Sum256([]byte(id.String()))] = net.Port(route)
	}
	return identity, hashes
}

// AddUser implements proxy.UserManager.AddUser().
func (s *Server) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	if u == nil || u.Account == nil {
		return errors.New("anytls: invalid user")
	}
	acc, ok := u.Account.(*MemoryAccount)
	if !ok {
		return errors.New("anytls: invalid account type")
	}
	if acc.Password == "" {
		return errors.New("anytls: user password required")
	}

	identity, hashes := passwordHashes(acc.Password)

	s.userMu.Lock()
	defer s.userMu.Unlock()

	prev := s.usersByID[identity]
	if prev != nil && prev.Email != u.Email {
		return errors.New("anytls: user identity already exists with a different email")
	}
	if u.Email != "" {
		prev = s.usersByEmail[u.Email]
	}
	for sum := range hashes {
		if auth, ok := s.users[sum]; ok && auth.user != prev {
			return errors.New("anytls: user password already exists")
		}
	}
	if prev != nil {
		s.removeUserLocked(prev)
	}
	// Keep a server-owned identity so callers cannot mutate indexed credentials.
	user := *u
	account := *acc
	user.Account = &account
	for sum, route := range hashes {
		s.users[sum] = authenticatedUser{user: &user, route: route}
	}
	s.usersByID[identity] = &user
	if user.Email != "" {
		s.usersByEmail[user.Email] = &user
	}
	return nil
}

// removeUserLocked removes every authentication variant of one logical user.
func (s *Server) removeUserLocked(user *protocol.MemoryUser) {
	identity, hashes := passwordHashes(user.Account.(*MemoryAccount).Password)
	for sum := range hashes {
		delete(s.users, sum)
	}
	delete(s.usersByID, identity)
	if user.Email != "" {
		delete(s.usersByEmail, user.Email)
	}
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (s *Server) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("anytls: empty email")
	}

	s.userMu.Lock()
	defer s.userMu.Unlock()

	if user, ok := s.usersByEmail[email]; ok {
		s.removeUserLocked(user)
	}
	return nil
}

// GetUser implements proxy.UserManager.GetUser().
func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}

	s.userMu.RLock()
	defer s.userMu.RUnlock()

	return s.usersByEmail[email]
}

// GetUsers implements proxy.UserManager.GetUsers().
func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	s.userMu.RLock()
	defer s.userMu.RUnlock()

	users := make([]*protocol.MemoryUser, 0, len(s.usersByID))
	for _, u := range s.usersByID {
		users = append(users, u)
	}
	return users
}

// GetUsersCount implements proxy.UserManager.GetUsersCount().
func (s *Server) GetUsersCount(ctx context.Context) int64 {
	s.userMu.RLock()
	defer s.userMu.RUnlock()

	return int64(len(s.usersByID))
}
