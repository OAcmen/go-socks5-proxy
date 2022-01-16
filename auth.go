package go_socks5_proxy

import (
	"fmt"
	"io"
)

const (
	NoAuth       = uint8(0)
	GssApi       = uint8(1)
	UserPassAuth = uint8(2)
	NoAcceptable = uint8(255)

	userAuthVersion = uint8(1)
	authSuccess     = uint8(0)
	authFailure     = uint8(1)
)

// AuthContext a Request encapsulates authentication state provided  during negotiation.
type AuthContext struct {
	// Provided auth method
	Method uint8
	// Payload provided during negotiation.
	// Keys depend on the used auth method.
	// eg: UserPassAuth contains Username.
	Payload map[string]string
}

type Authenticator interface {
	Authenticate(reader io.Reader, writer io.Writer) (*AuthContext, error)
	GetCode() uint8
}

// NoAuthAuthenticator is used to handle the "No Authentication" mode.
type NoAuthAuthenticator struct{}

func (noAuth NoAuthAuthenticator) Authenticate(reader io.Reader, writer io.Writer) (*AuthContext, error) {
	_, err := writer.Write([]byte{socks5Version, NoAuth})
	return &AuthContext{Method: NoAuth, Payload: nil}, err
}

func (noAuth NoAuthAuthenticator) GetCode() uint8 {
	return NoAuth
}

// UserPassAuthAuthenticator is used to handle username/password based authentication.
type UserPassAuthAuthenticator struct {
	Credentials Credential
}

func (userPassAuth UserPassAuthAuthenticator) GetCode() uint8 {
	return UserPassAuth
}

// Authenticate
/**
client username/password authentication message:
+---------+-----------------+----------+-----------------+----------+
| version | username length | username | password length | password |
+---------+-----------------+----------+-----------------+----------+
|    1    |        1        |  dynamic |        1        |  dynamic |
+---------+-----------------+----------+-----------------+----------+
*/
func (userPassAuth UserPassAuthAuthenticator) Authenticate(reader io.Reader, writer io.Writer) (*AuthContext, error) {
	// Reply the client to use username/password auth
	if _, err := writer.Write([]byte{socks5Version, UserPassAuth}); err != nil {
		return nil, err
	}

	// Read two bytes to get the version and username length
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(reader, header, 2); err != nil {
		return nil, err
	}

	// Version check
	if header[0] != userAuthVersion {
		return nil, fmt.Errorf("unsupported auth verison: %v", header[0])
	}

	usernameLength := int(header[1])
	username := make([]byte, usernameLength)
	if _, err := io.ReadAtLeast(reader, username, usernameLength); err != nil {
		return nil, err
	}

	// Read one byte to get password length
	if _, err := reader.Read(header[:1]); err != nil {
		return nil, err
	}

	passwordLen := int(header[0])
	password := make([]byte, passwordLen)
	if _, err := io.ReadAtLeast(reader, password, passwordLen); err != nil {
		return nil, err
	}

	// Verify the password
	if userPassAuth.Credentials.Valid(string(username), string(password)) {
		if _, err := writer.Write([]byte{userAuthVersion, authSuccess}); err != nil {
			return nil, err
		}
	} else {
		if _, err := writer.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return nil, err
		}
	}

	return &AuthContext{
		Method:  UserPassAuth,
		Payload: map[string]string{"Username": string(username)},
	}, nil
}
