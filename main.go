package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	socks5Version  = 0x05
	cmdConnect     = 0x01
	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x03
	bufferSize     = 4096
)

type client struct {
	conn net.Conn
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Port was not specified:(")
		return
	}

	port := os.Args[1]
	validatePort(port)

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			log.Printf("Error closing listener: %v\n", err)
		}
	}()

	log.Printf("SOCKS5 Proxy listening on port %s", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		log.Printf("New connection from %s", conn.RemoteAddr())
		go func() {
			if err := handleConnection(conn); err != nil {
				log.Printf("Error handling connection from %s: %v", conn.RemoteAddr(), err)
			}
		}()
	}
}

func validatePort(port string) {
	var p int
	p, _ = strconv.Atoi(port)
	if p < 0 || p > 65535 {
		log.Fatalf("Port must be between 0 and 65535")
	}
}

func handleConnection(conn net.Conn) error {
	defer func() {
		log.Printf("Connection closed: %s", conn.RemoteAddr())
		if err := conn.Close(); err != nil {
			log.Printf("Error closing connection: %v", err)
		}
	}()

	client := &client{conn: conn}

	if err := client.handleHandshake(); err != nil {
		return fmt.Errorf("handshake error: %w", err)
	}

	if err := client.handleRequest(); err != nil {
		return fmt.Errorf("request handling error: %w", err)
	}

	return nil
}

func (c *client) handleHandshake() error {
	buf := make([]byte, 2) //read version | n
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return fmt.Errorf("failed to read handshake: %w", err)
	}

	if buf[0] != socks5Version {
		return errors.New("invalid SOCKS version")
	}

	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(c.conn, methods); err != nil {
		return fmt.Errorf("failed to read methods: %w", err)
	}

	if _, err := c.conn.Write([]byte{socks5Version, 0x00}); err != nil { //0x00 - no authorisation
		return fmt.Errorf("failed to write handshake response: %w", err)
	}

	log.Printf("Handshake successful with %s", c.conn.RemoteAddr())
	return nil
}

func (c *client) handleRequest() error {
	buf := make([]byte, 4) //version | comand | rsv | atype
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return fmt.Errorf("failed to read request: %w", err)
	}

	if buf[0] != socks5Version {
		return errors.New("invalid SOCKS version")
	}

	if buf[1] != cmdConnect {
		return errors.New("unsupported command")
	}

	addrType := buf[3]
	var destAddr string
	var destPort uint16

	switch addrType {
	case addrTypeIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(c.conn, addr); err != nil {
			return fmt.Errorf("failed to read IPv4 address: %w", err)
		}
		destAddr = net.IP(addr).String()
	case addrTypeDomain:
		domainLen := make([]byte, 1)
		if _, err := c.conn.Read(domainLen); err != nil {
			return fmt.Errorf("failed to read domain length: %w", err)
		}
		domain := make([]byte, domainLen[0])
		if _, err := io.ReadFull(c.conn, domain); err != nil {
			return fmt.Errorf("failed to read domain name: %w", err)
		}
		destAddr = string(domain)
	default:
		return errors.New("invalid address type")
	}

	port := make([]byte, 2) //dest port
	if _, err := c.conn.Read(port); err != nil {
		return fmt.Errorf("failed to read port: %w", err)
	}
	destPort = binary.BigEndian.Uint16(port)

	remoteAddr := fmt.Sprintf("%s:%d", destAddr, destPort)
	log.Printf("Connecting to remote address: %s", remoteAddr)

	remoteConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		if _, writeErr := c.conn.Write([]byte{socks5Version, 0x01, 0x00, addrTypeIPv4, 0, 0, 0, 0, 0, 0}); writeErr != nil { //0x01 - respond error
			log.Printf("Error sending connection failure response: %v", writeErr)
		}
		return fmt.Errorf("failed to connect to remote address %s: %w", remoteAddr, err)
	}

	defer func() {
		if err := remoteConn.Close(); err != nil {
			log.Printf("Error closing remote connection: %v", err)
		}
	}()

	if _, err := c.conn.Write([]byte{socks5Version, 0x00, 0x00, addrTypeIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		return fmt.Errorf("failed to send success response: %w", err)
	}
	log.Printf("Connection established between %s and %s", c.conn.RemoteAddr(), remoteAddr)

	var wg sync.WaitGroup
	wg.Add(2)

	go transfer(c.conn, remoteConn, &wg)
	go transfer(remoteConn, c.conn, &wg)

	wg.Wait()
	log.Printf("Connection closed between %s and %s", c.conn.RemoteAddr(), remoteAddr)
	return nil
}

func transfer(src, dst net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()

	buf := make([]byte, bufferSize)
	for {
		n, err := src.Read(buf)
		if err == io.EOF {
			log.Printf("Connection finished gracefully: %s -> %s", src.RemoteAddr(), dst.RemoteAddr())
			if closeErr := dst.(*net.TCPConn).CloseWrite(); closeErr != nil {
				log.Printf("Error closing write on connection: %v", closeErr)
			}
			return
		} else if err != nil {
			log.Printf("Error reading data: %v", err)
			return
		}

		if n > 0 {
			err := dst.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err != nil {
				log.Printf("Error setting write deadline: %v", err)
				return
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				log.Printf("Error writing data: %v", err)
				return
			}
		}
	}
}
