package go_socks5_proxy

import "testing"

func TestPlaintextCredential_Valid(t *testing.T) {
	type args struct {
		user     string
		password string
	}
	tests := []struct {
		name string
		s    PlaintextCredential
		args args
		want bool
	}{
		// TODO: Add test cases.
		{
			name: "case1",
			s:    PlaintextCredential{"foo": "bar", "baz": ""},
			args: args{user: "foo", password: "bar"},
			want: true,
		},
		{
			name: "case2",
			s:    PlaintextCredential{"foo": "bar", "baz": ""},
			args: args{user: "baz", password: ""},
			want: true,
		},
		{
			name: "case3",
			s:    PlaintextCredential{"foo": "bar", "baz": ""},
			args: args{user: "foo", password: ""},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.Valid(tt.args.user, tt.args.password); got != tt.want {
				t.Errorf("Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}
