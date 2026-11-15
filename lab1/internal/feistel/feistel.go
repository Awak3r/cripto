package feistel

import (
	"bytes"
	"fmt"
	"reflect"

	"lab1/internal/interfaces"
)

type Network struct {
	ke      interfaces.KeyExpansion
	rt      interfaces.RoundTransform
	rounds  int
	keys    [][]byte
	keySize int
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
	keySize := 0
	for i := range owned {
		owned[i] = bytes.Clone(keys[i])
		keySize = max(keySize, len(keys[i]))
	}
	n.keys, n.keySize = owned, keySize
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
	return n.crypt(block, false)
}

func (n *Network) Decrypt(block interfaces.Block) interfaces.Block {
	return n.crypt(block, true)
}

func (n *Network) crypt(block interfaces.Block, decrypt bool) interfaces.Block {
	n.checkBlock(block)
	h := len(block) / 2
	halves := bytes.Clone(block)
	L, R := halves[:h:h], halves[h:len(block):len(block)]

	// Аргументы F изолированы от половин и расписания, но их буферы можно
	// переиспользовать: результат F потребляется до следующего раунда.
	// Буферы принадлежат вызову, поэтому параллельные операции независимы.
	scratch := make([]byte, h+n.keySize)
	input, key := scratch[:h:h], scratch[h:]
	for i := 0; i < n.rounds; i++ {
		round, source := i, R
		if decrypt {
			round, source = n.rounds-1-i, L
		}
		copy(input, source)
		roundKey := key[:len(n.keys[round]):len(n.keys[round])]
		copy(roundKey, n.keys[round])
		result := n.rt.Transform(input, roundKey)
		if decrypt {
			L, R = xor(R, result), L
		} else {
			L, R = R, xor(L, result)
		}
	}
	return append(L, R...)
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
