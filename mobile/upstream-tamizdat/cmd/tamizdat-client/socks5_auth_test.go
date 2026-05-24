package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type authTestDialer struct{}

func (authTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("test should not dial upstream during auth negotiation")
}

func (authTestDialer) DialUDP(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("test should not dial UDP upstream during auth negotiation")
}

func TestSocks5AuthSuccess(t *testing.T) {
	methodResp, authResp := exerciseSocks5Auth(t, []byte{0x05, 0x01, 0x02}, rfc1929AuthRequest("user", "pass"))
	if want := []byte{0x05, 0x02}; !bytes.Equal(methodResp, want) {
		t.Fatalf("method response = %v, want %v", methodResp, want)
	}
	if want := []byte{0x01, 0x00}; !bytes.Equal(authResp, want) {
		t.Fatalf("auth response = %v, want %v", authResp, want)
	}
}

func TestSocks5AuthFailure(t *testing.T) {
	methodResp, authResp := exerciseSocks5Auth(t, []byte{0x05, 0x01, 0x02}, rfc1929AuthRequest("user", "wrong"))
	if want := []byte{0x05, 0x02}; !bytes.Equal(methodResp, want) {
		t.Fatalf("method response = %v, want %v", methodResp, want)
	}
	if want := []byte{0x01, 0x01}; !bytes.Equal(authResp, want) {
		t.Fatalf("auth response = %v, want %v", authResp, want)
	}
}

func TestSocks5AuthRejectsMissingUserPassMethod(t *testing.T) {
	methodResp, authResp := exerciseSocks5Auth(t, []byte{0x05, 0x01, 0x00}, nil)
	if want := []byte{0x05, 0xff}; !bytes.Equal(methodResp, want) {
		t.Fatalf("method response = %v, want %v", methodResp, want)
	}
	if len(authResp) != 0 {
		t.Fatalf("auth response = %v, want none", authResp)
	}
}

func exerciseSocks5Auth(t *testing.T, greeting []byte, authReq []byte) ([]byte, []byte) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		handleSocks(conn, authTestDialer{}, socksConfig{AuthUser: "user", AuthPass: "pass"})
		done <- nil
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if _, err := client.Write(greeting); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	methodResp := readExact(t, client, 2)

	var authResp []byte
	if authReq != nil {
		if _, err := client.Write(authReq); err != nil {
			t.Fatalf("write auth request: %v", err)
		}
		authResp = readExact(t, client, 2)
	}

	_ = client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server handler: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server handler did not return")
	}

	return methodResp, authResp
}

func readExact(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return buf
}

func rfc1929AuthRequest(user, pass string) []byte {
	buf := []byte{0x01, byte(len(user))}
	buf = append(buf, user...)
	buf = append(buf, byte(len(pass)))
	buf = append(buf, pass...)
	return buf
}
