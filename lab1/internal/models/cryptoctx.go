package cryptoctx

import (
	"bytes"
	"fmt"

	"lab1/internal/interfaces"
)

type CipherMode int

const (
	ECB CipherMode = iota
	CBC
	PCBC
	CFB
	OFB
	CTR
	RandomDelta
)

type PaddingMode int

const (
	Zeros PaddingMode = iota
	ANSIX923
	PKCS7
	ISO10126
)

type Context struct {
	cipher     interfaces.BlockCipher
	mode       CipherMode
	padding    PaddingMode
	iv         []byte
	modeParams []any
}

func NewContext(factory func() interfaces.BlockCipher, mode CipherMode, padding PaddingMode, key, iv []byte, modeParams ...any) *Context {
	if factory == nil {
		panic("cryptoctx: не задана фабрика блочного шифра")
	}
	cipher := factory()
	if cipher == nil {
		panic("cryptoctx: фабрика вернула nil-шифр")
	}
	cipher.SetKey(bytes.Clone(key))
	return &Context{cipher, mode, padding, bytes.Clone(iv), append([]any(nil), modeParams...)}
}

func (c *Context) EncryptBytes(data, dst []byte) <-chan Result {
	return c.cryptBytes(data, dst, true)
}

func (c *Context) DecryptBytes(data, dst []byte) <-chan Result {
	return c.cryptBytes(data, dst, false)
}

func (c *Context) EncryptFile(inPath, outPath string) <-chan error {
	return c.cryptFile(inPath, outPath, true)
}

func (c *Context) DecryptFile(inPath, outPath string) <-chan error {
	return c.cryptFile(inPath, outPath, false)
}

func (c *Context) cryptBytes(data, dst []byte, encrypt bool) <-chan Result {
	ch := make(chan Result, 1)
	go func() {
		defer close(ch)
		out, err := c.apply(data, encrypt)
		if err == nil && dst != nil {
			if len(dst) < len(out) {
				out, err = nil, fmt.Errorf("недостаточная длина dst: %d, требуется %d", len(dst), len(out))
			} else {
				copy(dst, out)
			}
		}
		ch <- Result{out, err}
	}()
	return ch
}

type Result struct {
	Data []byte
	Err  error
}
