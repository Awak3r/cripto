package des

import (
	"fmt"

	"lab1/internal/feistel"
	"lab1/internal/interfaces"
	"lab1/internal/permutation"
)

var indexRule = permutation.IndexRule{FromLittle: false, Start: 1}

type KeyExpansion struct{}

func (KeyExpansion) Expand(key []byte) [][]byte {
	if len(key) != 8 {
		panic(fmt.Sprintf("ключ DES должен быть 8 байт, получено %d", len(key)))
	}
	cd := permutation.Permute(key, pc1, indexRule)
	keys := make([][]byte, 16)
	for r := 0; r < 16; r++ {
		rot(cd, 0, 28, shifts[r])
		rot(cd, 28, 56, shifts[r])
		keys[r] = permutation.Permute(cd, pc2, indexRule)
	}
	return keys
}

func rot(cd []byte, from, to, n int) {
	bits := to - from
	var v uint32
	for i := from; i < to; i++ {
		v = v<<1 | uint32(cd[i/8]>>(7-i%8)&1)
	}
	v = (v<<uint(n) | v>>uint(bits-n)) & (1<<bits - 1)
	for i := from; i < to; i++ {
		setBit28(cd, i, byte(v>>(to-1-i))&1)
	}
}

func setBit28(v []byte, index int, bit byte) {

	b, i := index/8, 7-index%8
	if bit == 1 {
		v[b] |= 1 << i
	} else {
		v[b] &^= 1 << i
	}
}

type RoundFunc struct{}

func (RoundFunc) Transform(block interfaces.Block, key []byte) interfaces.Block {
	if len(block) != 4 || len(key) != 6 {
		panic(fmt.Sprintf("DES: round requires a 4-byte block and 6-byte key, got %d and %d", len(block), len(key)))
	}
	e := permutation.Permute(block, expansion, indexRule)
	for i := range e {
		e[i] ^= key[i]
	}
	out := make([]byte, 4)
	for s := 0; s < 8; s++ {

		bit := func(k int) byte {
			idx := s*6 + k
			return e[idx/8] >> (7 - idx%8) & 1
		}
		row := bit(0)<<1 | bit(5)
		col := bit(1)<<3 | bit(2)<<2 | bit(3)<<1 | bit(4)
		v := sBoxes[s][row<<4|col]
		out[s/2] |= v << (4 * (1 - s%2))
	}
	return permutation.Permute(out, p, indexRule)
}

type Cipher struct {
	network *feistel.Network
}

func NewCipher() *Cipher {
	c := &Cipher{}
	c.network = feistel.NewNetwork(KeyExpansion{}, RoundFunc{}, 16)
	return c
}

func (c *Cipher) SetKey(key []byte) { c.network.SetKey(key) }

func (c *Cipher) BlockSize() int { return 8 }

func (c *Cipher) Encrypt(block interfaces.Block) interfaces.Block {
	if len(block) != 8 {
		panic(fmt.Sprintf("DES: block must be 8 bytes, got %d", len(block)))
	}
	x := permutation.Permute(block, ip, indexRule)
	return permutation.Permute(swap(c.network.Encrypt(x)), fp, indexRule)
}

func (c *Cipher) Decrypt(block interfaces.Block) interfaces.Block {
	if len(block) != 8 {
		panic(fmt.Sprintf("DES: block must be 8 bytes, got %d", len(block)))
	}

	x := permutation.Permute(block, ip, indexRule)
	return permutation.Permute(c.network.Decrypt(swap(x)), fp, indexRule)
}
func swap(b interfaces.Block) interfaces.Block {
	h := len(b) / 2
	return append(append([]byte(nil), b[h:]...), b[:h]...)
}
