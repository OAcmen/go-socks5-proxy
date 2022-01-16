package go_socks5_proxy

import (
	"bytes"
	"fmt"
	"testing"
)

func TestNoAuth(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{1, NoAuth})
	var resp bytes.Buffer

	s, _ := NewServer(&Config{})
	ctx, err := s.authenticate(&resp, req)
	if err != nil {
		t.Fatalf("err:%v", err)
	}

	if ctx.Method != NoAuth {
		t.Fatalf("Invalid Context Method")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, NoAuth}) {
		t.Fatalf("bad:%v", out)
	}
}

func TestPasswordAuth_Valid(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	var resp bytes.Buffer

	cred := PlaintextCredential{
		"foo": "bar",
	}

	cator := UserPassAuthAuthenticator{Credentials: cred}
	s, _ := NewServer(&Config{AuthMethods: []Authenticator{cator}})

	fmt.Println(s)
	fmt.Println(req.Bytes())
	ctx, err := s.authenticate(&resp, req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	fmt.Println(ctx)
	fmt.Println(resp.Bytes())

	if ctx.Method != UserPassAuth {
		t.Fatal("Invalid Context Method")
	}

	val, ok := ctx.Payload["Username"]
	if !ok {
		t.Fatal("Missing key Username in auth context's payload")
	}

	if val != "foo" {
		t.Fatal("Invalid Username in auth context's payload")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, UserPassAuth, 1, authSuccess}) {
		t.Fatalf("bad: %v", out)
	}
}
