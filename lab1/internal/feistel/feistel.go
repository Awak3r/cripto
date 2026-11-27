package feistel

import (
	"bytes"

	"lab1/internal/interfaces"
)

type Network struct {
	ke     interfaces.KeyExpansion
	rt     interfaces.RoundTransform
	rounds int
	keys   [][]byte
}

func NewNetwork(ke interfaces.KeyExpansion, rt interfaces.RoundTransform, rounds int) *Network {
	if ke == nil || rt == nil || rounds <= 0 {
		panic("некорректные параметры сети Фейстеля")
	}
	return &Network{ke: ke, rt: rt, rounds: rounds}
}

func (n *Network) SetKey(key []byte) {
	keys := n.ke.Expand(bytes.Clone(key))
	if len(keys) < n.rounds {
		panic("недостаточно раундовых ключей")
	}
	n.keys = make([][]byte, n.rounds)
	for i := range n.keys {
		n.keys[i] = bytes.Clone(keys[i])
	}
}

func (n *Network) split(block interfaces.Block) ([]byte, []byte) {
	if len(n.keys) != n.rounds || len(block) == 0 || len(block)%2 != 0 {
		panic("некорректный блок или не задан ключ")
	}
	h := len(block) / 2
	return bytes.Clone(block[:h]), bytes.Clone(block[h:])
}

func (n *Network) Encrypt(block interfaces.Block) interfaces.Block {
	L, R := n.split(block)
	for _, key := range n.keys {
		f := n.rt.Transform(bytes.Clone(R), bytes.Clone(key))
		L, R = R, xor(L, f)
	}
	return append(L, R...)
}

func (n *Network) Decrypt(block interfaces.Block) interfaces.Block {
	L, R := n.split(block)
	for i := n.rounds - 1; i >= 0; i-- {
		f := n.rt.Transform(bytes.Clone(L), bytes.Clone(n.keys[i]))
		L, R = xor(R, f), L
	}
	return append(L, R...)
}

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("некорректная длина результата F")
	}
	for i := range a {
		a[i] ^= b[i]
	}
	return a
}
