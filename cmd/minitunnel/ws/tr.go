package ws

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/bramstera/minitu/cmd/minitunnel/ws/dns"
)

// HandleTrojan handles Trojan-WS protocol connections.
// On success it blocks until the connection ends and returns true.
func HandleTrojan(ws *websocket.Conn, msg []byte, uuid string) bool {
	if len(msg) < 58 {
		return false
	}

	receivedHash := string(msg[0:56])
	hash := sha256.Sum224([]byte(uuid))
	expectedHash := hex.EncodeToString(hash[:])
	if receivedHash != expectedHash {
		return false
	}

	offset := 56

	if offset+1 < len(msg) && msg[offset] == 0x0d && msg[offset+1] == 0x0a {
		offset += 2
	}

	if offset >= len(msg) || msg[offset] != 0x01 {
		return false
	}
	offset++

	if offset >= len(msg) {
		return false
	}
	atyp := msg[offset]
	offset++

	host, ro, ok := parseAddr(msg, offset, atyp)
	if !ok {
		return false
	}
	offset = ro

	if len(msg) < offset+2 {
		return false
	}
	port := binary.BigEndian.Uint16(msg[offset : offset+2])
	offset += 2

	if offset+1 < len(msg) && msg[offset] == 0x0d && msg[offset+1] == 0x0a {
		offset += 2
	}

	resolvedIP, err := dns.ResolveHost(host)
	if err != nil {
		resolvedIP = host
	}

	targetAddr := fmt.Sprintf("%s:%d", resolvedIP, port)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		ws.Close()
		return false
	}
	defer conn.Close()

	if offset < len(msg) {
		conn.Write(msg[offset:])
	}

	pipe(ws, conn)
	return true
}

// parseAddr parses an address at msg[offset] given the address type atyp.
// Returns the host string, the new offset, and ok.
func parseAddr(msg []byte, offset int, atyp byte) (host string, newOffset int, ok bool) {
	switch atyp {
	case 0x01: // IPv4
		if len(msg) < offset+4 {
			return "", 0, false
		}
		host = fmt.Sprintf("%d.%d.%d.%d", msg[offset], msg[offset+1], msg[offset+2], msg[offset+3])
		return host, offset + 4, true
	case 0x03: // Domain
		if len(msg) < offset+1 {
			return "", 0, false
		}
		domainLen := int(msg[offset])
		offset++
		if len(msg) < offset+domainLen {
			return "", 0, false
		}
		host = string(msg[offset : offset+domainLen])
		return host, offset + domainLen, true
	case 0x04: // IPv6
		if len(msg) < offset+16 {
			return "", 0, false
		}
		ipv6 := msg[offset : offset+16]
		var parts []string
		for i := 0; i < 16; i += 2 {
			parts = append(parts, fmt.Sprintf("%x", binary.BigEndian.Uint16(ipv6[i:i+2])))
		}
		return strings.Join(parts, ":"), offset + 16, true
	default:
		return "", 0, false
	}
}

// pipe relays data between a websocket and a tcp connection until either side closes.
func pipe(ws *websocket.Conn, conn net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(conn, &wsReader{ws})
		done <- struct{}{}
	}()
	go func() {
		io.Copy(&wsWriter{ws}, conn)
		done <- struct{}{}
	}()
	<-done
}
