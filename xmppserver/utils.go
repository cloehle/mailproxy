package xmppserver

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// Cookie is used to give a unique identifier to each request.
type Cookie uint64

func createCookie() Cookie {
	var buf [8]byte
	if _, err := rand.Reader.Read(buf[:]); err != nil {
		panic("Failed to read random bytes: " + err.Error())
	}
	return Cookie(binary.LittleEndian.Uint64(buf[:]))
}

// We need this outside of this package but want to keep the rest of xmppserver
// code as close to original as possible
func CreateCookie() Cookie {
	return createCookie()
}

func makeResource() string {
	var buf [16]byte
	if _, err := rand.Reader.Read(buf[:]); err != nil {
		panic("Failed to read random bytes: " + err.Error())
	}
	return fmt.Sprintf("%x", buf)
}
