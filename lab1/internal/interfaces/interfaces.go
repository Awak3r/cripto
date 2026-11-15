package interfaces

type Block []byte

// KeyExpansion возвращает расписание, которое сеть копирует при SetKey.
// Возвращённые ключи должны оставаться неизменными до завершения SetKey.
type KeyExpansion interface {
	Expand(key []byte) [][]byte
}

// RoundTransform может изменять блок и ключ: сеть передаёт изолированные копии.
// Аргументы доступны только во время вызова; затем сеть переиспользует их память.
// Результат может ссылаться на аргументы, но не на общий изменяемый буфер.
// Преобразование должно зависеть только от аргументов и быть потокобезопасным.
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
