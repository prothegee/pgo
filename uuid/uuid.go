package pgo

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// --------------------------------------------------------- //

// 128 bit (16 byte) uuid as defined in RFC 4122
type UUID [16]byte

// --------------------------------------------------------- //

type UUIDv1Generator struct {
	Mtx           sync.Mutex
	LastTimestamp uint64
	ClockSeq      uint16
	Node          [6]byte
}

const (
	gregorianOffset = uint64(122192928000000000)
	clockSeqMask    = uint16(0x3fff)
)

var (
	GlobalGeneratorV1     *UUIDv1Generator
	GlobalGeneratorV1Once sync.Once
	GlobalGeneratorV1Err  error
)

func GetNodeID() ([6]byte, error) {
	// strat:
	// try get address from non-loopback interface
	// if fail, use random multicast (RFC 4122:4.5)
	//
	// get MAC address from network interface
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			// skip loopback & point-to-point interfaces
			if iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
				continue
			}
			// get interface with MAC address 6-byte
			if len(iface.HardwareAddr) == 6 {
				var node [6]byte
				copy(node[:], iface.HardwareAddr)
				return node, nil
			}
		}
	}

	// fallback random multicast
	randomNode := make([]byte, 6)
	if _, err := rand.Read(randomNode); err != nil {
		return [6]byte{}, fmt.Errorf("fail to generate random node ID: %w", err)
	}
	randomNode[0] |= 0x01 // multicast bit

	var node [6]byte
	copy(node[:], randomNode)
	return node, nil
}

func GetRandom14Bit() (uint16, error) {
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b) & clockSeqMask, nil
}

// timestamp 60-bit in 100 nanoseconds since 1582-10-15 intervals
func getTimestamp() uint64 {
	unixTime := time.Now().UnixNano() / 100 // 100-ns intervals
	return uint64(unixTime) + gregorianOffset
}

// uuid v7 RFC 4122 compliant
func (g *UUIDv1Generator) NewV1() (string, error) {
	g.Mtx.Lock()
	defer g.Mtx.Unlock()

	timestamp := getTimestamp()

	var clockSeq uint16
	var err error

	switch {
	case g.LastTimestamp == 0:
		// first time init
		clockSeq, err = GetRandom14Bit()
		if err != nil {
			return "", err
		}

	case timestamp < g.LastTimestamp:
		// clock regression (time backward) - increment clock seq
		clockSeq = (g.ClockSeq + 1) & clockSeqMask

	case timestamp == g.LastTimestamp:
		// same timestamp - increment clock seq
		clockSeq = (g.ClockSeq + 1) & clockSeqMask
		if clockSeq == 0 {
			// overflow clock seq (16384 uuid in the same 100 nanoseconds)
			// wait till timestamp changed (RFC 4122:4.2.1.1)
			for timestamp == g.LastTimestamp {
				time.Sleep(time.Microsecond)
				timestamp = getTimestamp()
			}
			// set clock seq to random val after waited
			clockSeq, err = GetRandom14Bit()
			if err != nil {
				return "", err
			}
		}

	default:
		// forward timestamp - reset clock seq to rand val
		clockSeq, err = GetRandom14Bit()
		if err != nil {
			return "", err
		}
	}

	// save for for next generate
	g.LastTimestamp = timestamp
	g.ClockSeq = clockSeq

	// uuid v1 (RFC 4122 section 4.2)
	timeLow := uint32(timestamp & 0xFFFFFFFF)
	timeMid := uint16((timestamp >> 32) & 0xFFFF)
	timeHiAndVersion := uint16((timestamp>>48)&0x0FFF) | 0x1000 // v1

	clockSeqLow := uint8(clockSeq & 0xFF)
	clockSeqHiAndVariant := uint8((clockSeq>>8)&0x3F) | 0x80 // variant RFC 4122

	// byte array uuid (16 byte)
	uuid := make([]byte, 16)
	binary.BigEndian.PutUint32(uuid[0:4], timeLow)
	binary.BigEndian.PutUint16(uuid[4:6], timeMid)
	binary.BigEndian.PutUint16(uuid[6:8], timeHiAndVersion)
	uuid[8] = clockSeqHiAndVariant
	uuid[9] = clockSeqLow
	copy(uuid[10:16], g.Node[:])

	return fmt.Sprintf("%x-%x-%x-%x-%x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16],
	), nil
}

func NewUUIDv1Generator() (*UUIDv1Generator, error) {
	node, err := GetNodeID()
	if err != nil {
		return nil, fmt.Errorf("fail to initialize node ID: %w", err)
	}

	// try init random clock seq (14-bit)
	clockSeq, err := GetRandom14Bit()
	if err != nil {
		return nil, fmt.Errorf("fail to initialize clock sequence: %w", err)
	}

	return &UUIDv1Generator{
		LastTimestamp: 0,
		ClockSeq:      clockSeq,
		Node:          node,
	}, nil
}

// generate uuid v1
func UUIDv1() (UUID, error) {
	res, _ := UUIDv1asString()
	return UUIDfromString(res)
}

// generate uuid v1 as string
//
// return: string, err
func UUIDv1asString() (string, error) {
	GlobalGeneratorV1Once.Do(func() {
		GlobalGeneratorV1, GlobalGeneratorV1Err = NewUUIDv1Generator()
	})
	if GlobalGeneratorV1Err != nil {
		return "", fmt.Errorf("fail to initialize uuid v1: %w", GlobalGeneratorV1Err)
	}
	return GlobalGeneratorV1.NewV1()
}

// --------------------------------------------------------- //

// generate uuid v4
func UUIDv4() (UUID, error) {
	res, _ := UUIDv4asString()
	return UUIDfromString(res)
}

// generate uuid v4 as string
//
// return: string, err
func UUIDv4asString() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "uuid_v4-error#1", err
	}

	// set version 4 to 7th byte [6]
	b[6] = (b[6] & 0x0f) | 0x40 // 0100xxxx

	// rfc 4122 variant to 9th byte [8]
	b[8] = (b[8] & 0x3f) | 0x80 // 10xxxxxx

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// --------------------------------------------------------- //

type UUIDGeneratorV7 struct {
	Mtx        sync.Mutex
	LastMillis int64
	Counter    uint16 // 12-bit counter (0-4095)
}

var (
	GeneratorV7     *UUIDGeneratorV7
	GeneratorV7Once sync.Once
	GeneratorV7Err  error
)

// helper PutUint48 since not available in stl
func PutUint48(b []byte, v uint64) {
	_ = b[5] // bounds check hint
	b[0] = byte(v >> 40)
	b[1] = byte(v >> 32)
	b[2] = byte(v >> 24)
	b[3] = byte(v >> 16)
	b[4] = byte(v >> 8)
	b[5] = byte(v)
}

// NewUUIDGeneratorV7 export constructor for testing
func NewUUIDGeneratorV7() (*UUIDGeneratorV7, error) {
	return &UUIDGeneratorV7{
		LastMillis: 0,
		Counter:    0,
	}, nil
}

// NewV7 export method to generate UUID v7 from generator (for testing)
func (g *UUIDGeneratorV7) NewV7() (string, error) {
	g.Mtx.Lock()
	defer g.Mtx.Unlock()

	now := time.Now().UnixMilli()

	// reset counter if millisecond changed
	if now != g.LastMillis {
		g.LastMillis = now
		g.Counter = 0
	}

	var counterBits uint16
	if g.Counter < 4095 {
		// inline counter
		counterBits = g.Counter
		g.Counter++
	} else {
		// overflow use random bits of 12-bit (RFC 9562:6.2)
		randBuf := make([]byte, 2)
		if _, err := rand.Read(randBuf); err != nil {
			return "", err
		}
		counterBits = binary.BigEndian.Uint16(randBuf) & 0x0FFF // get 12 bit
	}

	// gen uuid v7 RFC 9562 compliant
	uuid := make([]byte, 16)

	// 48-bit timestamp (unix millisecond)
	PutUint48(uuid[0:6], uint64(now))

	// 4-bit version (7) + 12-bit counter/random
	uuid[6] = (7 << 4) | byte(counterBits>>8) // 0111xxxx
	uuid[7] = byte(counterBits)

	// 2-bit variant (10) + 62-bit random
	randBuf := make([]byte, 10)
	if _, err := rand.Read(randBuf); err != nil {
		return "", err
	}
	uuid[8] = (randBuf[0] & 0x3F) | 0x80 // 10xxxxxx
	copy(uuid[9:], randBuf[1:])

	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

// generate uuid v7
func UUIDv7() (UUID, error) {
	res, _ := UUIDv7asString()
	return UUIDfromString(res)
}

// generate uuid v7 as string
//
// return: string, err
func UUIDv7asString() (string, error) {
	GeneratorV7Once.Do(func() {
		GeneratorV7, GeneratorV7Err = NewUUIDGeneratorV7()
	})
	if GeneratorV7Err != nil {
		return "", fmt.Errorf("fail to initialize uuid v7: %w", GeneratorV7Err)
	}

	GeneratorV7.Mtx.Lock()
	defer GeneratorV7.Mtx.Unlock()

	now := time.Now().UnixMilli()

	// reset counter if millisecond changed
	if now != GeneratorV7.LastMillis {
		GeneratorV7.LastMillis = now
		GeneratorV7.Counter = 0
	}

	var counterBits uint16
	if GeneratorV7.Counter < 4095 {
		// inline counter
		counterBits = GeneratorV7.Counter
		GeneratorV7.Counter++
	} else {
		// overflow use random bits of 12-bit (RFC 9562:6.2)
		randBuf := make([]byte, 2)
		if _, err := rand.Read(randBuf); err != nil {
			return "", err
		}
		counterBits = binary.BigEndian.Uint16(randBuf) & 0x0FFF // get 12 bit
	}

	// gen uuid v7 RFC 9562 compliant
	uuid := make([]byte, 16)

	// 48-bit timestamp (unix millisecond)
	PutUint48(uuid[0:6], uint64(now))

	// 4-bit version (7) + 12-bit counter/random
	uuid[6] = (7 << 4) | byte(counterBits>>8) // 0111xxxx
	uuid[7] = byte(counterBits)

	// 2-bit variant (10) + 62-bit random
	randBuf := make([]byte, 10)
	if _, err := rand.Read(randBuf); err != nil {
		return "", err
	}
	uuid[8] = (randBuf[0] & 0x3F) | 0x80 // 10xxxxxx
	copy(uuid[9:], randBuf[1:])

	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

// --------------------------------------------------------- //

var xvalues = [256]byte{
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255,
	255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
}

func xToByte(x1, x2 byte) (byte, bool) {
	b1 := xvalues[x1]
	b2 := xvalues[x2]
	return (b1 << 4) | b2, b1 != 255 && b2 != 255
}

func UUIDfromString(s string) (UUID, error) {
	var uuid UUID

	switch len(s) {
	case 32:
		var ok bool
		for i := range uuid {
			uuid[i], ok = xToByte(s[i*2], s[i*2+1])
			if !ok {
				return uuid, fmt.Errorf("wrong uuid format")
			}
		}
		return uuid, nil
	case 36:
		// ok
	case 36 + 2:
		s = s[1:]
	case 36 + 9:
		if !strings.EqualFold(s[:9], "urn:uuid:") {
			return uuid, fmt.Errorf("wrong urn prefix: %q", s[:9])
		}
		s = s[9:]
	default:
		return uuid, fmt.Errorf("wrong uuid length: %d", len(s))
	}

	// at least 36 bytes long
	// and looks like: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return uuid, fmt.Errorf("wrong uuid format")
	}

	for i, x := range [16]int{0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34} {
		val, ok := xToByte(s[x], s[x+1])
		if !ok {
			return uuid, fmt.Errorf("invalid uuid format")
		}
		uuid[i] = val
	}

	return uuid, nil
}

func UUIDfromBytes(b []byte) (UUID, error) {
	var uuid UUID

	switch len(b) {
	case 32:
		var ok bool
		for i := 0; i < 32; i += 2 {
			uuid[i/2], ok = xToByte(b[i], b[i+1])
			if !ok {
				return uuid, fmt.Errorf("wrong uuid format")
			}
		}
		return uuid, nil
	case 36:
		// ok
	case 36 + 2:
		b = b[1:]
	case 36 + 9:
		if !bytes.EqualFold(b[:9], []byte("urn:uuid")) {
			return uuid, fmt.Errorf("wrong urn:prefix: %q", b[:9])
		}
		b = b[9:]
	default:
		return uuid, fmt.Errorf("wrong uuid format")
	}

	// at least 36 bytes long
	// and looks like: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	if b[8] != '-' || b[13] != '-' || b[18] != '-' || b[23] != '-' {
		return uuid, fmt.Errorf("wrong uuid format")
	}

	for i, x := range [16]int{0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34} {
		val, ok := xToByte(b[x], b[x+1])
		if !ok {
			return uuid, fmt.Errorf("invalid uuid format")
		}
		uuid[i] = val
	}

	return uuid, nil
}
