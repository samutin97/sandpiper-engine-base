package socks

import (
	std_bufio "bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type refusingHandler struct{}

func (refusingHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	conn.Close()
}

func (refusingHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	conn.Close()
}

// W4-06: the error of a failed SOCKS authentication, which the inbound logs with the source
// address, names neither the user name nor the password the client sent.
func TestH_FailedAuthenticationKeepsCredentialsOutOfTheError(t *testing.T) {
	const sentUser, sentPassword = "probe-user-name", "probe-password-value"
	authenticator := auth.NewAuthenticator([]auth.User{{Username: "real-user", Password: "real-password-value"}})
	for _, version := range []byte{5, 4} {
		server, client := net.Pipe()
		done := make(chan error, 1)
		go func() {
			done <- HandleConnectionEx(context.Background(), server, std_bufio.NewReader(server), authenticator,
				refusingHandler{}, nil, time.Minute, M.Socksaddr{}, nil)
			server.Close()
		}()
		go func() {
			defer client.Close()
			if version == 5 {
				client.Write([]byte{5, 1, 2})
				reply := make([]byte, 2)
				if _, err := io.ReadFull(client, reply); err != nil {
					return
				}
				request := []byte{1, byte(len(sentUser))}
				request = append(request, sentUser...)
				request = append(request, byte(len(sentPassword)))
				request = append(request, sentPassword...)
				client.Write(request)
			} else {
				// CONNECT 192.0.2.1:443 with a user id
				request := []byte{4, 1, 1, 187, 192, 0, 2, 1}
				request = append(request, sentUser...)
				client.Write(append(request, 0))
			}
			io.Copy(io.Discard, client)
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("socks%d: a wrong password was let in", version)
			}
			message := err.Error()
			if !strings.Contains(message, "authentication failed") {
				t.Fatalf("socks%d: %q", version, message)
			}
			for _, secret := range []string{sentUser, sentPassword, "real-user", "real-password-value"} {
				if strings.Contains(message, secret) {
					t.Errorf("socks%d: %q holds %q", version, message, secret)
				}
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("socks%d: no answer", version)
		}
	}
}
