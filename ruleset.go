package go_socks5_proxy

import (
	"context"
)

// RuleSet is used to provide custom rules to allow or prohibit actions
type RuleSet interface {
	Allow(ctx context.Context, req *Request) bool
}

// PermitAll returns a RuleSet which allows all types of connections.
func PermitAll() RuleSet {
	return &PermitCommand{
		EnableConnect:   true,
		EnableBind:      true,
		EnableAssociate: true,
	}
}

// PermitNone returns a RuleSet which disallows all types of connections.
func PermitNone() RuleSet {
	return &PermitCommand{
		EnableConnect:   false,
		EnableBind:      false,
		EnableAssociate: false,
	}
}

type PermitCommand struct {
	EnableConnect   bool
	EnableBind      bool
	EnableAssociate bool
}

func (p *PermitCommand) Allow(ctx context.Context, req *Request) bool {
	switch req.Command {
	case ConnectCommand:
		return p.EnableConnect
	case BindCommand:
		return p.EnableBind
	case AssociateCommand:
		return p.EnableAssociate
	}

	return false
}
