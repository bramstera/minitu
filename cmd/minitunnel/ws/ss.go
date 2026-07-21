package ws

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/bramstera/minitu/cmd/minitunnel/ws/dns"
	"github.com/gorilla/websocket"
)

// HandleShadowsocks handles Shadowsocks-WS protocol connections
func HandleShadowsocks(ws *websocket.Conn, msg []byte) bool {
	if len(msg) < 1 {
		return false
	}

	offset := 0
	atyp := msg[offset]
	offset++

	var host string

	switch atyp {
	case 0x01: // IPv4
		if len(msg) < offset+4 {
			return false
		}
		host = fmt.Sprintf("%d.%d.%d.%d", msg[offset], msg[offset+1], msg[offset+2], msg[offset+3])
		offset += 4

	case 0x03: // Domain
		if len(msg) < offset+1 {
			return false
		}
		domainLen := int(msg[offset])
		offset++
		if len(msg) < offset+domainLen {
			return false
		}
		host = string(msg[offset : offset+domainLen])
		offset += domainLen

	case 0x04: // IPv6
		if len(msg) < offset+16 {
			return false
		}
		ipv6 := msg[offset : offset+16]
		var parts []string
		for i := 0; i < 16; i += 2 {
			parts = append(parts, fmt.Sprintf("%x", binary.BigEndian.Uint16(ipv6[i:i+2])))
		}
		host = strings.Join(parts, ":")
		offset += 16

	default:
		return false
	}

	if len(msg) < offset+2 {
		return false
	}
	port := binary.BigEndian.Uint16(msg[offset : offset+2])
	offset += 2

	// Resolve host
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

	go io.Copy(conn, &wsReader{ws})
	io.Copy(&wsWriter{ws}, conn)

	return true
}
