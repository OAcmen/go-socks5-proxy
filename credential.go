package go_socks5_proxy

// Credential is used to support user/password authentication.
type Credential interface {
	Valid(user, password string) bool
}

type PlaintextCredential map[string]string

func (s PlaintextCredential) Valid(user, password string) bool {
	pass, ok := s[user]
	if !ok {
		return false
	}
	return pass == password
}
