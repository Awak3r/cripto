package deal

import (
	"fmt"
	"sync"

	"lab1/internal/des"
	"lab1/internal/feistel"
	"lab1/internal/interfaces"
)

type KeyExpansion struct{}

func (KeyExpansion) Expand(key []byte) [][]byte {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		panic(fmt.Sprintf("ключ DEAL должен быть 16, 24 или 32 байта, получено %d", len(key)))
	}
	rounds := 6
	if len(key) == 32 {
		rounds = 8
	}
	e := des.NewCipher()
	e.SetKey([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
	parts := len(key) / 8
	constants := [...]byte{0x80, 0x40, 0x10, 0x01}
	keys := make([][]byte, rounds)
	prev := make([]byte, 8)
	for i := range keys {
		block := make([]byte, 8)
		for j := range block {
			block[j] = key[(i%parts)*8+j] ^ prev[j]
		}
		if i >= parts {
			block[0] ^= constants[i-parts]
		}
		prev = e.Encrypt(block)
		keys[i] = prev
	}
	return keys
}

type RoundFunc struct {
	ciphers sync.Map
}

func (rf *RoundFunc) Transform(block interfaces.Block, key []byte) interfaces.Block {
	k := string(key)
	if v, ok := rf.ciphers.Load(k); ok {
		return v.(*des.Cipher).Encrypt(block)
	}
	c := des.NewCipher()
	c.SetKey(key)
	v, _ := rf.ciphers.LoadOrStore(k, c)
	return v.(*des.Cipher).Encrypt(block)
}

type Cipher struct {
	network *feistel.Network
}

var _ interfaces.BlockCipher = (*Cipher)(nil)

func NewCipher() *Cipher {
	return &Cipher{feistel.NewNetwork(KeyExpansion{}, &RoundFunc{}, 6)}
}

func (c *Cipher) SetKey(key []byte) {
	rounds := 6
	if len(key) == 32 {
		rounds = 8
	}

	n := feistel.NewNetwork(KeyExpansion{}, &RoundFunc{}, rounds)
	n.SetKey(key)
	c.network = n
}

func (c *Cipher) BlockSize() int { return 16 }

func (c *Cipher) Encrypt(block interfaces.Block) interfaces.Block {
	return swap(c.network.Encrypt(swap(block)))
}

func (c *Cipher) Decrypt(block interfaces.Block) interfaces.Block {
	return swap(c.network.Decrypt(swap(block)))
}

func swap(block interfaces.Block) interfaces.Block {
	if len(block) != 16 {
		panic(fmt.Sprintf("блок DEAL должен быть 16 байт, получено %d", len(block)))
	}
	out := make([]byte, 16)
	copy(out, block[8:])
	copy(out[8:], block[:8])
	return out
}
