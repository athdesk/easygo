package connutil

import (
	"fmt"
	"log"
	"net"
	ss "strings"
)

//GetMacAddr gets machine's own MAC address
func GetMacAddr() (string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var as []string
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		if a != "" {
			as = append(as, a)
		}
	}

	mac := ss.Join(as, "")

	return mac, nil
}

//TODO Actually use BufferSize as a buffer
type EnhancedConn struct {
	simpleConn net.Conn
	BufferSize int
}

//EnhanceConn is the constructor for conn type
func EnhanceConn(sc net.Conn, bufferSize int) EnhancedConn {
	c := EnhancedConn{}
	c.simpleConn = sc
	c.BufferSize = bufferSize
	return c
}

//Send converts string to bytes and sends it
func (ec EnhancedConn) Send(msg string) bool {
	bytes := []byte(msg)
	_, err := ec.simpleConn.Write(bytes)
	if err != nil {
		return false
	}
	return true
}

//SendBytes sends bytes directly
func (ec EnhancedConn) SendBytes(data []byte) bool {
	_, err := ec.simpleConn.Write(data)
	if err != nil {
		return false
	}
	return true
}

//SendByte sends one byte directly
func (ec EnhancedConn) SendByte(data byte) bool {
	slice := make([]byte, 1)
	slice[0] = data
	_, err := ec.simpleConn.Write(slice)
	if err != nil {
		return false
	}
	return true
}

//Read waits for remote to send data, and returns string (4KiB MAX)
func (ec EnhancedConn) Read() string {
	//chunkSize := ec.BufferSize
	conn := ec.simpleConn
	buf := make([]byte, 8192) // big buffer

	_, err := conn.Read(buf)

	if err != nil {
		fmt.Println(err)
	}

	nval := ""
	for _, current := range buf {
		if current != 0 {
			nval += string(current)
		} else {
			break
		}
	}

	return nval
}

//ReadBytes returns null-stripped data in byte form
func (ec EnhancedConn) ReadBytes(bufferSize int) ([]byte, error) {
	conn := ec.simpleConn
	buf := make([]byte, bufferSize)

	_, err := conn.Read(buf)

	var nval []byte
	for _, current := range buf { //strips data from null bytes
		if current != 0 {
			nval = append(nval, current)
		}
	}

	return nval, err
}

//ReadByte reads and returns only one byte from the stream
func (ec EnhancedConn) ReadByte() byte {
	conn := ec.simpleConn
	temp := make([]byte, 1)

	_, err := conn.Read(temp)
	if err != nil {
		log.Print(err)
	}

	return temp[0]

}

//SetMessageEvent calls the provided function every time a message is received
func (ec EnhancedConn) SetMessageEvent(handle func([]byte)) {
	go func() {
		for {
			var err error
			err = nil
			data, err := ec.ReadBytes(ec.BufferSize)
			if err != nil {
				log.Print(err)
				ec.Close()
				break
			}
			handle(data)
		}
	}()
}

//Close function closes connection
func (ec EnhancedConn) Close() {
	ec.simpleConn.Close()
}
