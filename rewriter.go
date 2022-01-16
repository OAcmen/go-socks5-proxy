package go_socks5_proxy

import "context"

// AddressRewriter is used to rewrite a destination transparently.
type AddressRewriter interface {
	Rewrite(ctx context.Context, request *Request) (context.Context, *Socks5AddrType)
}
