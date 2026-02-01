package pgo

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// --------------------------------------------------------- //

type UUIDv1Generator struct {
	mu            sync.Mutex
	lastTimestamp uint64
	clockSeq      uint16
	node          [6]byte
}

const (
	gregorianOffset = uint64(122192928000000000)
	clockSeqMask    = uint16(0x3fff)
)

var (
	globalGenerator     *UUIDv1Generator
	globalGeneratorOnce sync.Once
	globalGeneratorErr  error
)

func getNodeID() ([6]byte, error) {
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
		return [6]byte{}, fmt.Errorf("gagal generate random node ID: %w", err)
	}
	randomNode[0] |= 0x01 // multicast bit

	var node [6]byte
	copy(node[:], randomNode)
	return node, nil
}

func getRandom14Bit() (uint16, error) {
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b) & clockSeqMask, nil
}

// get timestamp 60-bit in 100 nanoseconds since 1582-10-15 intervals
func getTimestamp() uint64 {
	unixTime := time.Now().UnixNano() / 100 // 100-ns intervals
	return uint64(unixTime) + gregorianOffset
}

// uuid v7 RFC 4122 compliant
func (g *UUIDv1Generator) new() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	timestamp := getTimestamp()

	var clockSeq uint16
	var err error

	switch {
	case g.lastTimestamp == 0:
		// first time init
		clockSeq, err = getRandom14Bit()
		if err != nil {
			return "", err
		}

	case timestamp < g.lastTimestamp:
		// clock regression (time backward) - increment clock seq
		clockSeq = (g.clockSeq + 1) & clockSeqMask

	case timestamp == g.lastTimestamp:
		// same timestamp - increment clock seq
		clockSeq = (g.clockSeq + 1) & clockSeqMask
		if clockSeq == 0 {
			// overflow clock seq (16384 uuid in the same 100 nanoseconds)
			// wait till timestamp changed (RFC 4122:4.2.1.1)
			for timestamp == g.lastTimestamp {
				time.Sleep(time.Microsecond)
				timestamp = getTimestamp()
			}
			// set clock seq to random val after waited
			clockSeq, err = getRandom14Bit()
			if err != nil {
				return "", err
			}
		}

	default:
		// forward timestamp - reset clock seq to rand val
		clockSeq, err = getRandom14Bit()
		if err != nil {
			return "", err
		}
	}

	// save for for next generate
	g.lastTimestamp = timestamp
	g.clockSeq = clockSeq

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
	copy(uuid[10:16], g.node[:])

	return fmt.Sprintf("%x-%x-%x-%x-%x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16],
	), nil
}

func newUUIDv1Generator() (*UUIDv1Generator, error) {
	node, err := getNodeID()
	if err != nil {
		return nil, fmt.Errorf("gagal menginisialisasi node ID: %w", err)
	}

	// try init random clock seq (14-bit)
	clockSeq, err := getRandom14Bit()
	if err != nil {
		return nil, fmt.Errorf("gagal menginisialisasi clock sequence: %w", err)
	}

	return &UUIDv1Generator{
		lastTimestamp: 0,
		clockSeq:      clockSeq,
		node:          node,
	}, nil
}

//

// @brief generate uuid v1 (without MAC Address)
//
// @note one-time usage only
//
// @note do not use in goroutine (goroutine safe postpone)
//
// @return string, err
func UUIDv1() (string, error) {
	globalGeneratorOnce.Do(func() {
		globalGenerator, globalGeneratorErr = newUUIDv1Generator()
	})
	if globalGeneratorErr != nil {
		return "", fmt.Errorf("inisialisasi UUID v1 gagal: %w", globalGeneratorErr)
	}
	return globalGenerator.new()
}

// --------------------------------------------------------- //

// @brief generate uuid v4
//
// @return string, err
func UUIDv4() (string, error) {
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

type UUIDv7Generator struct {
	mu         sync.Mutex
	lastMillis int64
	counter    uint16 // 12-bit counter (0-4095)
}

var (
	v7Generator     *UUIDv7Generator
	v7GeneratorOnce sync.Once
	v7GeneratorErr  error
)

// helper putUint48 since not available in stl
func putUint48(b []byte, v uint64) {
	_ = b[5] // bounds check hint
	b[0] = byte(v >> 40)
	b[1] = byte(v >> 32)
	b[2] = byte(v >> 24)
	b[3] = byte(v >> 16)
	b[4] = byte(v >> 8)
	b[5] = byte(v)
}

func newUUIDv7Generator() (*UUIDv7Generator, error) {
	return &UUIDv7Generator{
		lastMillis: 0,
		counter:    0,
	}, nil
}

// @brief generate uuid v7
//
// @note one-time usage only
//
// @note do not use in goroutine (goroutine safe postpone)
//
// @return string, err
func UUIDv7() (string, error) {
	v7GeneratorOnce.Do(func() {
		v7Generator, v7GeneratorErr = newUUIDv7Generator()
	})
	if v7GeneratorErr != nil {
		return "", fmt.Errorf("inisialisasi UUID v7 gagal: %w", v7GeneratorErr)
	}

	v7Generator.mu.Lock()
	defer v7Generator.mu.Unlock()

	now := time.Now().UnixMilli()

	// reset counter if millisecond changed
	if now != v7Generator.lastMillis {
		v7Generator.lastMillis = now
		v7Generator.counter = 0
	}

	var counterBits uint16
	if v7Generator.counter < 4095 {
		// inline counter
		counterBits = v7Generator.counter
		v7Generator.counter++
	} else {
		// Overflow: gunakan 12-bit random bits (RFC 9562 section 6.2)
		// overflow use random bits of 12-bit (RFC 9562:6.2)
		randBuf := make([]byte, 2)
		if _, err := rand.Read(randBuf); err != nil {
			return "", err
		}
		counterBits = binary.BigEndian.Uint16(randBuf) & 0x0FFF // get 12 bit
	}

	// Bangun UUID v7 sesuai RFC 9562
	// gen uuid v7 RFC 9562 compliant
	uuid := make([]byte, 16)

	// 48-bit timestamp (unix millisecond)
	putUint48(uuid[0:6], uint64(now))

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
