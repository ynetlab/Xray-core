package anytls

import (
	"context"
	"crypto/sha256"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/uuidroute"
)

func newUserValidator(router routing.Router) *uuidroute.Validator {
	return uuidroute.NewValidator(router, func(password string) string {
		hash := sha256.Sum256([]byte(password))
		return string(hash[:])
	}, func(email string) string { return email })
}

// AddUser implements proxy.UserManager.AddUser, replacing an existing Email.
func (s *Server) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	credential, err := userCredential(user)
	if err != nil {
		return err
	}
	return s.validator.Add(credential.User, credential.Password, true)
}

func userCredential(user *protocol.MemoryUser) (uuidroute.Credential, error) {
	if user == nil || user.Account == nil {
		return uuidroute.Credential{}, errors.New("anytls: invalid user")
	}
	account, ok := user.Account.(*MemoryAccount)
	if !ok {
		return uuidroute.Credential{}, errors.New("anytls: invalid account type")
	}
	if account.Password == "" {
		return uuidroute.Credential{}, errors.New("anytls: user password required")
	}
	userCopy, accountCopy := *user, *account
	userCopy.Account = &accountCopy
	return uuidroute.Credential{User: &userCopy, Password: accountCopy.Password}, nil
}

func (s *Server) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("anytls: empty email")
	}
	_, err := s.validator.Remove(email)
	return err
}

func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}
	return s.validator.GetByEmail(email)
}

func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	return s.validator.GetAll()
}

func (s *Server) GetUsersCount(ctx context.Context) int64 {
	return s.validator.GetCount()
}
