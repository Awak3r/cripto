// Package rc6 implements the RC6-32/20 block cipher described in the AES submission.
package rc6

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math/bits"
)

// BlockSize is the RC6-32/20 block size in bytes.
const BlockSize = 16

const (
	rounds      = 20
	logWordSize = 5
	p32         = 0xb7e15163
	q32         = 0x9e3779b9
)

type rc6Cipher struct {
	roundKeys [2*rounds + 4]uint32
}

// NewCipher creates an RC6-32/20 cipher with a 16-, 24-, or 32-byte key.
func NewCipher(key []byte) (cipher.Block, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("rc6: invalid key size %d bytes", len(key))
	}

	wordCount := len(key) / 4
	var keyWords [8]uint32
	for i := range wordCount {
		keyWords[i] = binary.LittleEndian.Uint32(key[4*i:])
	}

	block := new(rc6Cipher)
	keys := &block.roundKeys
	keys[0] = p32
	for i := 1; i < len(keys); i++ {
		keys[i] = keys[i-1] + q32
	}

	// The expanded schedule has more words than any supported input key.
	var a, b uint32
	i, j := 0, 0
	for range 3 * len(keys) {
		a = bits.RotateLeft32(keys[i]+a+b, 3)
		keys[i] = a
		b = bits.RotateLeft32(keyWords[j]+a+b, int((a+b)&31))
		keyWords[j] = b
		i = (i + 1) % len(keys)
		j = (j + 1) % wordCount
	}
	return block, nil
}

func (*rc6Cipher) BlockSize() int { return BlockSize }

func (rc *rc6Cipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize || len(dst) < BlockSize {
		panic("rc6: input and output must contain a full block")
	}
	a := binary.LittleEndian.Uint32(src[0:4])
	b := binary.LittleEndian.Uint32(src[4:8]) + rc.roundKeys[0]
	c := binary.LittleEndian.Uint32(src[8:12])
	d := binary.LittleEndian.Uint32(src[12:16]) + rc.roundKeys[1]

	for i := 1; i <= rounds; i++ {
		t := bits.RotateLeft32(b*(2*b+1), logWordSize)
		u := bits.RotateLeft32(d*(2*d+1), logWordSize)
		a = bits.RotateLeft32(a^t, int(u&31)) + rc.roundKeys[2*i]
		c = bits.RotateLeft32(c^u, int(t&31)) + rc.roundKeys[2*i+1]
		a, b, c, d = b, c, d, a
	}

	binary.LittleEndian.PutUint32(dst[0:4], a+rc.roundKeys[2*rounds+2])
	binary.LittleEndian.PutUint32(dst[4:8], b)
	binary.LittleEndian.PutUint32(dst[8:12], c+rc.roundKeys[2*rounds+3])
	binary.LittleEndian.PutUint32(dst[12:16], d)
}

func (rc *rc6Cipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize || len(dst) < BlockSize {
		panic("rc6: input and output must contain a full block")
	}
	a := binary.LittleEndian.Uint32(src[0:4]) - rc.roundKeys[2*rounds+2]
	b := binary.LittleEndian.Uint32(src[4:8])
	c := binary.LittleEndian.Uint32(src[8:12]) - rc.roundKeys[2*rounds+3]
	d := binary.LittleEndian.Uint32(src[12:16])

	for i := rounds; i >= 1; i-- {
		a, b, c, d = d, a, b, c
		t := bits.RotateLeft32(b*(2*b+1), logWordSize)
		u := bits.RotateLeft32(d*(2*d+1), logWordSize)
		c = bits.RotateLeft32(c-rc.roundKeys[2*i+1], -int(t&31)) ^ u
		a = bits.RotateLeft32(a-rc.roundKeys[2*i], -int(u&31)) ^ t
	}

	binary.LittleEndian.PutUint32(dst[0:4], a)
	binary.LittleEndian.PutUint32(dst[4:8], b-rc.roundKeys[0])
	binary.LittleEndian.PutUint32(dst[8:12], c)
	binary.LittleEndian.PutUint32(dst[12:16], d-rc.roundKeys[1])
}
