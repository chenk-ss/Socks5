package socks5

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
)

func Cmd() {
	log.Println("start socks5 proxy server")
	addrStr := ":1080"
	addr, err := net.ResolveTCPAddr("tcp", addrStr)
	if err != nil {
		log.Fatalf("can not resolve address %s, %s\n", addrStr, err)
	}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Fatalf("can not listent at address %s, %s\n", addr, err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("can not accept conn, %s\n", err)
				continue
			}
			go handle(conn)
		}
	}()
}

func handle(conn net.Conn) {
	defer conn.Close()
	bf := bufio.NewReader(conn)
	bs, err := bf.Peek(1)
	if err != nil {
		log.Printf("peek error %s\n", err)
	}
	switch bs[0] {
	case 0x04:
		log.Printf("socks version 4\n")
		return
	case 0x05:
		log.Printf("socks version 5\n")
	default:
		log.Printf("Unkown protocol")
		return
	}
	log.Println(bf.Peek(4))
	if a, err := doAuth(conn, bf); err != nil || !a {
		if err != nil {
			log.Printf("error %s\n", err)
		} else {
			log.Printf("auth fail!")
		}
		return
	}
	doRequest(conn, bf)
}

func doRequest(conn net.Conn, bf *bufio.Reader) {
	parseRequest(conn, bf)
}

func parseRequest(conn net.Conn, bf *bufio.Reader) {
	data := make([]byte, 1024)
	size, err := bf.Read(data)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("read size: %d, data: %v\n", size, data[:size])
	if data[0] != S5Version {
		return
	}
	if data[1] != CommandConnect && data[1] != CommandBind && data[1] != CommandUdpAssociate {
		return
	}
	if data[3] != AddrTypeIPv4 && data[3] != AddrTypeDomain && data[3] != AddrTypeIPv6 {
		return
	}
	command := data[1]
	addrType := data[3]
	var addr string
	var port uint16
	portIndex := -1
	switch addrType {
	case AddrTypeIPv4:
		portIndex = 4 + 4
		b := bytes.Buffer{}
		for i := 4; i < 8; i++ {
			b.WriteString(strconv.FormatUint(uint64(data[i]), 10))
			if i != 7 {
				b.WriteByte('.')
			}
		}
		port = binary.BigEndian.Uint16(data[portIndex : portIndex+2])
		addr = b.String()
	case AddrTypeDomain:
		domainLen := data[4]
		portIndex = 5 + int(domainLen)
		port = binary.BigEndian.Uint16(data[portIndex : portIndex+2])
		addr = string(data[5:portIndex])
	case AddrTypeIPv6:
		portIndex = 4 + 16
		b := bytes.Buffer{}
		b.WriteByte('[')
		for i := 4; i < 20; i = i + 2 {
			b.WriteString(strconv.FormatUint(uint64(binary.BigEndian.Uint16(data[i:i+2])), 16))
			if i != 18 {
				b.WriteByte(':')
			}
		}
		b.WriteByte(']')
		port = binary.BigEndian.Uint16(data[portIndex : portIndex+2])
		addr = b.String()
	}

	log.Printf("command: %v, addr: %v, port: %v\n", command, addr, port)
	var addrStr string
	if addrType == AddrTypeIPv6 {
		addrStr = "[" + addr + "]:" + strconv.Itoa(int(port))
	} else {
		addrStr = addr + ":" + strconv.Itoa(int(port))
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", addrStr)
	if err != nil {
		log.Printf("err %s\n", err)
		return
	}
	switch command {
	case CommandConnect:
		rconn, err := net.DialTCP("tcp", nil, tcpAddr)
		if err != nil {
			log.Printf("err %s\n", err)
			return
		}
		defer rconn.Close()
		m := make([]byte, 10)
		m[0] = S5Version
		m[1] = 0x00
		m[3] = 0x01
		tAddr := rconn.LocalAddr().(*net.TCPAddr)
		log.Println(tAddr)
		copy(m[4:8], tAddr.IP)
		binary.BigEndian.PutUint16(m[8:10], uint16(tAddr.Port))
		log.Println(m)
		conn.Write(m)
		transport(conn, rconn)
	case CommandBind:
	case CommandUdpAssociate:
	}
}

func doAuth(conn net.Conn, bf *bufio.Reader) (bool, error) {
	var data = make([]byte, 257)
	_, err := bf.Read(data)
	if err != nil {
		log.Printf("err read %s\n", err)
		return false, err
	}

	methodList := data[2 : 2+data[1]]
	authAcc := false
	noAuth := false
	for _, v := range methodList {
		if v == MethodAccPwd {
			authAcc = true
		} else if v == MethodNoAuth {
			noAuth = true
		}
		if noAuth && authAcc {
			break
		}
	}

	m := make([]byte, 2)
	m[0] = uint8(0x05)
	if authAcc {
		m[1] = MethodAccPwd
	} else if noAuth {
		m[1] = MethodNoAuth
	} else {
		m[1] = MethodNoAcceptable
	}
	conn.Write(m)
	if authAcc {
		data := make([]byte, 1024)
		_, err := bf.Read(data)
		if err != nil {
			log.Printf("err read %s\n", err)
			return false, err
		}
		//log.Printf("read size %v\n", size)
		//log.Printf("data: %v\n", data[:size])
		if data[0] != S5AuthVer {
			m[0] = S5AuthVer
			m[1] = 0xFF
			conn.Write(m)
			return false, errors.New(fmt.Sprintf("value %v for version of auth method is not expected", data[0]))
		}
		accLen := data[1]
		pwdLen := data[2+accLen]
		acc := data[2 : accLen+2]
		pwd := data[accLen+3 : accLen+3+pwdLen]
		log.Printf("acc: %s, pwd: %s\n", acc, pwd)
		m[0] = S5AuthVer
		m[1] = 0x00
		conn.Write(m)
		return true, nil
	} else if noAuth {
		return true, nil
	} else {
		return false, errors.New("no acceptable method for auth")
	}
}

func transport(rw1, rw2 io.ReadWriter) {
	errc := make(chan error, 1)
	go func() {
		errc <- copyBuffer(rw1, rw2)
	}()
	go func() {
		errc <- copyBuffer(rw2, rw1)
	}()
	err := <-errc
	if err != nil && err != io.EOF {
		return
	}
}

var lPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
}

func copyBuffer(dst io.Writer, src io.Reader) error {
	buf := lPool.Get().([]byte)
	defer lPool.Put(buf)

	_, err := io.CopyBuffer(dst, src, buf)
	return err
}
