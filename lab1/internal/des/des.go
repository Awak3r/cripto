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
		panic("ключ DES должен быть 8 байт")
	}
	cd := permutation.Permute(key, pc1, indexRule)
	keys := make([][]byte, 16)
	for r := range keys {
		cd = rotateHalves(cd, shifts[r])
		keys[r] = permutation.Permute(cd, pc2, indexRule)
	}
	return keys
}

func rotateHalves(cd []byte, shift int) []byte {
	order := make([]int, 56)
	for i := 0; i < 28; i++ {
		order[i] = (i+shift)%28 + 1
		order[i+28] = order[i] + 28
	}
	return permutation.Permute(cd, order, indexRule)
}

type RoundFunc struct{}

func (RoundFunc) Transform(block interfaces.Block, key []byte) interfaces.Block {
	if len(block) != 4 || len(key) != 6 {
		panic("DES: раунд требует блок 4 байта и ключ 6 байт")
	}
	expanded := permutation.Permute(block, expansion, indexRule)
	for i := range expanded {
		expanded[i] ^= key[i]
	}
	substituted := applySBoxes(expanded)
	return permutation.Permute(substituted, p, indexRule)
}

func applySBoxes(data []byte) []byte {
	out := make([]byte, 4)
	for s := 0; s < 8; s++ {
		var six byte
		for j := 0; j < 6; j++ {
			i := s*6 + j
			bit := (data[i/8] >> (7-i%8)) & 1
			six = (six << 1) | bit
		}
		row := ((six >> 5) << 1) | (six & 1)
		col := (six >> 1) & 15
		value := sBoxes[s][int(row)*16+int(col)]
		if s%2 == 0 {
			out[s/2] = value << 4
		} else {
			out[s/2] |= value
		}
	}
	return out
}

type Cipher struct {
	network *feistel.Network
}

func NewCipher() *Cipher {
	return &Cipher{feistel.NewNetwork(KeyExpansion{}, RoundFunc{}, 16)}
}

func (c *Cipher) SetKey(key []byte) { c.network.SetKey(key) }

func (c *Cipher) BlockSize() int { return 8 }

func (c *Cipher) Encrypt(block interfaces.Block) interfaces.Block {
	if len(block) != 8 {
		panic(fmt.Sprintf("DES: блок должен быть 8 байт, получено %d", len(block)))
	}
	x := permutation.Permute(block, ip, indexRule)
	x = swap(c.network.Encrypt(x))
	return permutation.Permute(x, fp, indexRule)
}

func (c *Cipher) Decrypt(block interfaces.Block) interfaces.Block {
	if len(block) != 8 {
		panic(fmt.Sprintf("DES: блок должен быть 8 байт, получено %d", len(block)))
	}
	x := permutation.Permute(block, ip, indexRule)
	x = c.network.Decrypt(swap(x))
	return permutation.Permute(x, fp, indexRule)
}

func swap(b interfaces.Block) interfaces.Block {
	h := len(b) / 2
	return append(append([]byte(nil), b[h:]...), b[:h]...)
}
