// Package magenta implements the MAGENTA block cipher described in the AES submission.
package magenta

import (
	"crypto/cipher"
	"fmt"
)

// BlockSize is the MAGENTA block size in bytes.
const BlockSize = 16

const halfSize = BlockSize / 2

type magentaCipher struct {
	roundKeys [8][halfSize]byte
	rounds    int
}

// NewCipher creates a MAGENTA cipher with a 16-, 24-, or 32-byte key.
func NewCipher(key []byte) (cipher.Block, error) {
	// The indices refer to the eight-byte key parts in equation (9).
	var order []int
	switch len(key) {
	case 16:
		order = []int{0, 0, 1, 1, 0, 0}
	case 24:
		order = []int{0, 1, 2, 2, 1, 0}
	case 32:
		order = []int{0, 1, 2, 3, 3, 2, 1, 0}
	default:
		return nil, fmt.Errorf("magenta: invalid key size %d bytes", len(key))
	}

	block := &magentaCipher{rounds: len(order)}
	for round, part := range order {
		copy(block.roundKeys[round][:], key[part*halfSize:(part+1)*halfSize])
	}
	return block, nil
}

func (*magentaCipher) BlockSize() int { return BlockSize }

func (c *magentaCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize || len(dst) < BlockSize {
		panic("magenta: input and output must contain a full block")
	}
	left, right := c.encryptHalves([halfSize]byte(src[:halfSize]), [halfSize]byte(src[halfSize:BlockSize]))
	copy(dst[:halfSize], left[:])
	copy(dst[halfSize:BlockSize], right[:])
}

func (c *magentaCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize || len(dst) < BlockSize {
		panic("magenta: input and output must contain a full block")
	}
	// The palindromic key schedule gives Dec = V(Enc(V(src))), with V swapping halves.
	left, right := c.encryptHalves([halfSize]byte(src[halfSize:BlockSize]), [halfSize]byte(src[:halfSize]))
	copy(dst[:halfSize], right[:])
	copy(dst[halfSize:BlockSize], left[:])
}

func (c *magentaCipher) encryptHalves(left, right [halfSize]byte) ([halfSize]byte, [halfSize]byte) {
	for _, key := range c.roundKeys[:c.rounds] {
		mask := roundFunction(right, key)
		for i := range left {
			left[i] ^= mask[i]
		}
		left, right = right, left
	}
	return left, right
}

// roundFunction returns E^(3) of the right half followed by the round key.
func roundFunction(right, key [halfSize]byte) [halfSize]byte {
	var input [BlockSize]byte
	copy(input[:halfSize], right[:])
	copy(input[halfSize:], key[:])

	state := transform(input)
	for range 2 {
		// Equation (6) groups the even and odd bytes before XORing with the input.
		var mixed [BlockSize]byte
		for i := range halfSize {
			mixed[i] = input[i] ^ state[2*i]
			mixed[halfSize+i] = input[halfSize+i] ^ state[2*i+1]
		}
		state = transform(mixed)
	}

	var result [halfSize]byte
	for i := range result {
		result[i] = state[2*i]
	}
	return result
}

// transform is T = Π⁴. Each Π applies PE to pairs from opposite halves.
func transform(state [BlockSize]byte) [BlockSize]byte {
	for range 4 {
		var next [BlockSize]byte
		for i := range halfSize {
			x, y := state[i], state[halfSize+i]
			next[2*i] = exponent[x^exponent[y]]
			next[2*i+1] = exponent[y^exponent[x]]
		}
		state = next
	}
	return state
}

var exponent = makeExponentTable()

// makeExponentTable builds f(x) = α^x in GF(2⁸), with f(255) = 0.
func makeExponentTable() [256]byte {
	const polynomial = 0x165 // x⁸ + x⁶ + x⁵ + x² + 1
	var table [256]byte
	value := uint16(1)
	for i := range 255 {
		table[i] = byte(value)
		value <<= 1
		if value&0x100 != 0 {
			value ^= polynomial
		}
	}
	return table
}
