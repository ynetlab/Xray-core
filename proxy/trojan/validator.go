package trojan

import (
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/uuidroute"
)

// Validator stores valid trojan users. Its zero value remains usable.
type Validator struct {
	router routing.Router
	once   sync.Once
	index  *uuidroute.Validator
}

func (v *Validator) userIndex() *uuidroute.Validator {
	v.once.Do(func() {
		v.index = uuidroute.NewValidator(v.router, func(password string) string {
			return hexString(hexSha224(password))
		}, strings.ToLower)
	})
	return v.index
}

// Add a trojan user, Email must be empty or unique.
func (v *Validator) Add(user *protocol.MemoryUser) error {
	return v.addUsers([]*protocol.MemoryUser{user})
}

func (v *Validator) addUsers(users []*protocol.MemoryUser) error {
	credentials := make([]uuidroute.Credential, 0, len(users))
	for _, user := range users {
		if user == nil {
			return errors.New("invalid trojan user")
		}
		account, ok := user.Account.(*MemoryAccount)
		if !ok {
			return errors.New("invalid trojan account type")
		}
		userCopy, accountCopy := *user, *account
		accountCopy.Key = append([]byte(nil), account.Key...)
		userCopy.Account = &accountCopy
		credentials = append(credentials, uuidroute.Credential{User: &userCopy, Password: accountCopy.Password})
	}
	return v.userIndex().AddUsers(credentials, false)
}

// Del a trojan user with a non-empty Email.
func (v *Validator) Del(email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}
	removed, err := v.userIndex().Remove(email)
	if err != nil {
		return err
	}
	if !removed {
		return errors.New("User ", email, " not found.")
	}
	return nil
}

// Get preserves the existing hashed-key lookup interface.
func (v *Validator) Get(hash string) *protocol.MemoryUser {
	user, _ := v.GetWithRoute(hash)
	return user
}

func (v *Validator) GetWithRoute(hash string) (*protocol.MemoryUser, net.Port) {
	match := v.userIndex().Authenticate(hash)
	return match.User, match.Route
}

func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	return v.userIndex().GetByEmail(email)
}

// GetAll retains the existing API's Email-addressable user list.
func (v *Validator) GetAll() []*protocol.MemoryUser {
	users := v.userIndex().GetAll()
	result := make([]*protocol.MemoryUser, 0, len(users))
	for _, user := range users {
		if user.Email != "" {
			result = append(result, user)
		}
	}
	return result
}

func (v *Validator) GetCount() int64 {
	return int64(len(v.GetAll()))
}
