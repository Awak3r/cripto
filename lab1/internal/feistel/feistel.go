package feistel

import (
	"bytes"
	"fmt"
	"reflect"

	"lab1/internal/interfaces"
)

type Network struct {
	ke     interfaces.KeyExpansion
	rt     interfaces.RoundTransform
	rounds int
	keys   [][]byte
}

func NewNetwork(ke interfaces.KeyExpansion, rt interfaces.RoundTransform, rounds int) *Network {
	if rounds <= 0 {
		panic("feistel: rounds must be positive")
	}
	if isNil(ke) || isNil(rt) {
		panic("feistel: key expansion and round transform must be non-nil")
	}
	return &Network{ke: ke, rt: rt, rounds: rounds}
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	switch reflect.ValueOf(v).Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflect.ValueOf(v).IsNil()
	}
	return false
}

func (n *Network) SetKey(key []byte) {
	keys := n.ke.Expand(bytes.Clone(key))
	if len(keys) < n.rounds {
		panic(fmt.Sprintf("feistel: need at least %d round keys, got %d", n.rounds, len(keys)))
	}
	owned := make([][]byte, n.rounds)
	for i := range owned {
		owned[i] = bytes.Clone(keys[i])
	}
	n.keys = owned
}

func (n *Network) checkBlock(block interfaces.Block) {
	if len(n.keys) < n.rounds || n.rounds <= 0 {
		panic("feistel: call SetKey before Encrypt or Decrypt")
	}
	if len(block) == 0 || len(block)%2 != 0 {
		panic("feistel: block length must be positive and even")
	}
}

func (n *Network) Encrypt(block interfaces.Block) interfaces.Block {
	n.checkBlock(block)
	h := len(block) / 2
	L := append([]byte(nil), block[:h]...)
	R := append([]byte(nil), block[h:]...)
	for i := 0; i < n.rounds; i++ {
		L, R = R, xor(L, n.transform(R, i))
	}
	return append(L, R...)
}

func (n *Network) Decrypt(block interfaces.Block) interfaces.Block {
	n.checkBlock(block)
	h := len(block) / 2
	L := append([]byte(nil), block[:h]...)
	R := append([]byte(nil), block[h:]...)
	for i := n.rounds - 1; i >= 0; i-- {
		L, R = xor(R, n.transform(L, i)), L
	}
	return append(L, R...)
}

// Раундовая функция может изменять свои аргументы, но не рабочие половины
// сети и не сохранённое расписание ключей.
func (n *Network) transform(block interfaces.Block, round int) interfaces.Block {
	return n.rt.Transform(bytes.Clone(block), bytes.Clone(n.keys[round]))
}

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic(fmt.Sprintf("feistel: round transform must return %d bytes, got %d", len(a), len(b)))
	}
	for i := range a {
		a[i] ^= b[i]
	}
	return a
}
