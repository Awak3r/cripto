package des

import (
	"encoding/binary"
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
	e := expansionLookup[0][block[0]] | expansionLookup[1][block[1]] |
		expansionLookup[2][block[2]] | expansionLookup[3][block[3]]
	k := uint64(binary.BigEndian.Uint32(key))<<16 | uint64(binary.BigEndian.Uint16(key[4:]))
	e ^= k
	v := spLookup[0][e>>42&63] | spLookup[1][e>>36&63] |
		spLookup[2][e>>30&63] | spLookup[3][e>>24&63] |
		spLookup[4][e>>18&63] | spLookup[5][e>>12&63] |
		spLookup[6][e>>6&63] | spLookup[7][e&63]
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, v)
	return out
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
	x := permuteBlock(block, &ipLookup)
	return permuteBlock(swap(c.network.Encrypt(x)), &fpLookup)
}

func (c *Cipher) Decrypt(block interfaces.Block) interfaces.Block {
	if len(block) != 8 {
		panic(fmt.Sprintf("DES: block must be 8 bytes, got %d", len(block)))
	}

	x := permuteBlock(block, &ipLookup)
	return permuteBlock(c.network.Decrypt(swap(x)), &fpLookup)
}
func swap(b interfaces.Block) interfaces.Block {
	h := len(b) / 2
	return append(append([]byte(nil), b[h:]...), b[:h]...)
}
