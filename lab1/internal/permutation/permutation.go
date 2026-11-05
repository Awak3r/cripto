package permutation

import "fmt"

type IndexRule struct {
	FromLittle bool
	Start      int
}

func bitPos(value []byte, index int, rule IndexRule) (byteIndex, bitIndex int) {
	index -= rule.Start
	if rule.FromLittle {
		return len(value) - 1 - index/8, index % 8
	}
	return index / 8, 7 - index%8
}

func getB(value []byte, index int, rule IndexRule) byte {
	b, i := bitPos(value, index, rule)
	return (value[b] >> i) & 1
}

func setB(value []byte, index int, bit byte, rule IndexRule) {
	b, i := bitPos(value, index, rule)
	if bit == 1 {
		value[b] |= 1 << i
	} else {
		value[b] &^= 1 << i
	}
}

func Permute(value []byte, p []int, rule IndexRule) []byte {
	if rule.Start != 0 && rule.Start != 1 {
		panic("permutation: Start must be 0 or 1")
	}
	res := make([]byte, (len(p)+7)/8)
	for i := 0; i < len(p); i++ {
		if p[i] < rule.Start || p[i]-rule.Start >= len(value)*8 {
			panic(fmt.Sprintf("permutation: index p[%d]=%d outside input bits", i, p[i]))
		}
		setB(res, i+rule.Start, getB(value, p[i], rule), rule)
	}
	return res
}
