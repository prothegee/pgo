package pgo

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync/atomic"

	// "sync"
	"time"
)

// --------------------------------------------------------- //

var (
	lastMilisV7 uint64
	counterV7   uint32
)

// --------------------------------------------------------- //

// @brief generate uuid v1 (without MAC Address)
//
// @note one-time usage only
//
// @note do not use in goroutine (goroutine safe postpone)
//
// @return string, err
func UUIDv1() (string, error) {
	// 1: timestamp 100-ns since 1582-10-15
	now := time.Now()
	unixTime := now.UnixNano() / 100
	gregorianOffset := int64(122_192_928_000_000_000)
	timestamp := uint64(unixTime) + uint64(gregorianOffset)

	// 2: clock sequence (14-bit)
	clockSeq := make([]byte, 2)
	_, err := rand.Read(clockSeq)
	if err != nil {
		return "uuid_v1-error#2", err
	}
	clockSeq[0] = clockSeq[0] & 0x3f

	// 3: node id (48-bit); random bit multicast (40th bit = 1)
	node := make([]byte, 6)
	_, err = rand.Read(node)
	if err != nil {
		return "uuid_v1-error#3", err
	}
	node[0] = node[0] | 0x01

	b := make([]byte, 16)
	// low 32-bit
	binary.BigEndian.PutUint32(b[0:4], uint32(timestamp<<32>>32))
	// mid 16-bit
	binary.BigEndian.PutUint16(b[4:6], uint16(timestamp>>32))
	// time hi and version 1
	binary.BigEndian.PutUint16(b[6:8], uint16(timestamp>>48)&0x0fff|0x1000)

	// reserved clock variant RFC 4122
	b[8] = (clockSeq[0] & 0x3f) | 0x80
	b[9] = clockSeq[1]

	// node
	copy(b[10:], node)

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

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

// @brief generate uuid v7
//
// @note one-time usage only
//
// @note do not use in goroutine (goroutine safe postpone)
//
// @return string, err
func UUIDv7() (string, error) {
	// 1: timestamp milli since epoch
	now := time.Now().UnixMilli()
	atomic.StoreUint64(&lastMilisV7, uint64(now))

	// 2: counter 12-bit (uniqueness in 1 millisecond)
	cnt := atomic.AddUint32(&counterV7, 1) & 0x0fff

	// 3: random 62-bit for the rest field
	randBytes := make([]byte, 10)
	_, err := rand.Read(randBytes)
	if err != nil {
		return "uuid_v7-error#1", err
	}

	// 4: set bytes
	b := make([]byte, 16)

	// 48-bit timestamp (big-endian)
	b[0] = byte(now >> 40)
	b[1] = byte(now >> 32)
	b[2] = byte(now >> 24)
	b[3] = byte(now >> 16)
	b[4] = byte(now >> 8)
	b[5] = byte(now)

	// 4-bit version (7) + 12-bit counter
	b[6] = byte(0x70 | (cnt >> 8)) // v7 to the first 4
	b[7] = byte(cnt)

	// 2-bit variant (10) + 6-bit random
	b[8] = (randBytes[0] & 0x3f) | 0x80 // rfc 4122 variant
	copy(b[9:], randBytes[1:])

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
