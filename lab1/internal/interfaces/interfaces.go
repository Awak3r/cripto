package interfaces

type Block []byte

type KeyExpansion interface {
	Expand(key []byte) [][]byte
}

type RoundTransform interface {
	Transform(block Block, key []byte) Block
}

type BlockCipher interface {
	SetKey(key []byte)
	BlockSize() int
	Encrypt(block Block) Block
	Decrypt(block Block) Block
}
