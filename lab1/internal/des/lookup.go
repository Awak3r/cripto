package des

import (
	"encoding/binary"

	"lab1/internal/permutation"
)

// Each row holds one input byte's contribution, packed in big-endian order.
// The tables are built once from our DES tables and are read-only afterwards.
var (
	ipLookup        [8][256]uint64
	fpLookup        [8][256]uint64
	expansionLookup [4][256]uint64
	spLookup        [8][64]uint32
)

func init() {
	compilePermutation(ip, ipLookup[:])
	compilePermutation(fp, fpLookup[:])
	compilePermutation(expansion, expansionLookup[:])

	for s := range spLookup {
		for six := range spLookup[s] {
			row := (six>>4)&2 | six&1
			col := (six >> 1) & 15
			v := uint32(sBoxes[s][row*16+col]) << uint(28-4*s)
			var input [4]byte
			binary.BigEndian.PutUint32(input[:], v)
			spLookup[s][six] = binary.BigEndian.Uint32(permutation.Permute(input[:], p, indexRule))
		}
	}
}

func compilePermutation(table []int, rows [][256]uint64) {
	input := make([]byte, len(rows))
	for i := range rows {
		for value := range rows[i] {
			input[i] = byte(value)
			var packed uint64
			for _, b := range permutation.Permute(input, table, indexRule) {
				packed = packed<<8 | uint64(b)
			}
			rows[i][value] = packed
		}
		input[i] = 0
	}
}

func permuteBlock(block []byte, table *[8][256]uint64) []byte {
	v := table[0][block[0]] | table[1][block[1]] |
		table[2][block[2]] | table[3][block[3]] |
		table[4][block[4]] | table[5][block[5]] |
		table[6][block[6]] | table[7][block[7]]
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, v)
	return out
}
