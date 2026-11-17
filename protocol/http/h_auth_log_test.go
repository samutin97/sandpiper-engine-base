package http

import (
	std_bufio "bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
)

// W4-06: the error of a failed HTTP proxy authentication, which the inbound logs with the source
// address, holds no credential the client sent: not the user name, not the password, not the raw
// Proxy-Authorization header (a token, or a password with no name).
func TestH_FailedAuthenticationKeepsCredentialsOutOfTheError(t *testing.T) {
	const sentUser, sentPassword = "probe-user-name", "probe-password-value"
	authenticator := auth.NewAuthenticator([]auth.User{{Username: "real-user", Password: "real-password-value"}})
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(sentUser+":"+sentPassword))
	for _, header := range []string{basic, "Bearer " + sentPassword, "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+sentPassword)), ""} {
		server, client := net.Pipe()
		done := make(chan error, 1)
		go func() {
			done <- HandleConnectionEx(context.Background(), server, std_bufio.NewReader(server), authenticator, nil, M.Socksaddr{}, nil)
			server.Close()
		}()
		go func() {
			defer client.Close()
			request := "CONNECT 192.0.2.1:443 HTTP/1.1\r\nHost: 192.0.2.1:443\r\n"
			if header != "" {
				request += "Proxy-Authorization: " + header + "\r\n"
			}
			client.Write([]byte(request + "\r\n"))
			io.Copy(io.Discard, client)
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("%q: let in", header)
			}
			message := err.Error()
			if !strings.Contains(message, "authentication failed") {
				t.Fatalf("%q: %q", header, message)
			}
			for _, secret := range []string{sentUser, sentPassword, "real-user", "real-password-value", base64.StdEncoding.EncodeToString([]byte(sentUser))[:8]} {
				if strings.Contains(message, secret) {
					t.Errorf("%q: %q holds %q", header, message, secret)
				}
			}
			if header != "" && strings.Contains(message, "no Proxy-Authorization") {
				t.Errorf("%q: %q", header, message)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%q: no answer", header)
		}
	}
}
