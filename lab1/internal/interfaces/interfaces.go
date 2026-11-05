package interfaces

type Block []byte

// KeyExpansion возвращает расписание, которое сеть копирует при SetKey.
// Возвращённые ключи должны оставаться неизменными до завершения SetKey.
type KeyExpansion interface {
	Expand(key []byte) [][]byte
}

// RoundTransform может изменять переданные блок и ключ: сеть передаёт копии.
// Результат должен зависеть только от аргументов и не перезаписываться другими
// вызовами. Для параллельной работы сети Transform должен быть потокобезопасным.
type RoundTransform interface {
	Transform(block Block, key []byte) Block
}

// BlockCipher после SetKey должен допускать параллельные Encrypt и Decrypt.
// SetKey нельзя вызывать одновременно с ними. Результат каждого вызова
// принадлежит вызывающему коду и не перезаписывается последующими вызовами.
type BlockCipher interface {
	SetKey(key []byte)
	BlockSize() int
	Encrypt(block Block) Block
	Decrypt(block Block) Block
}
