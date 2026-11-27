package cryptoctx

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"runtime"
	"sync"
)

func validatePadding(bs int, mode PaddingMode) error {
	if bs <= 0 {
		return fmt.Errorf("некорректный размер блока: %d", bs)
	}
	if mode < Zeros || mode > ISO10126 {
		return fmt.Errorf("неизвестный режим набивки: %d", mode)
	}
	if mode != Zeros && bs > 255 {
		return fmt.Errorf("размер блока %d не помещается в байт длины набивки", bs)
	}
	return nil
}

func pad(data []byte, bs int, mode PaddingMode) ([]byte, error) {
	if err := validatePadding(bs, mode); err != nil {
		return nil, err
	}
	n := bs - len(data)%bs
	out := make([]byte, len(data)+n)
	copy(out, data)
	switch mode {
	case ANSIX923:
		out[len(out)-1] = byte(n)
	case PKCS7:
		for i := len(data); i < len(out); i++ {
			out[i] = byte(n)
		}
	case ISO10126:
		for i := len(data); i < len(out)-1; i++ {
			out[i] = byte(rand.Intn(256))
		}
		out[len(out)-1] = byte(n)
	}
	return out, nil
}

func unpad(data []byte, bs int, mode PaddingMode) ([]byte, error) {
	if err := validatePadding(bs, mode); err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data)%bs != 0 {
		return nil, fmt.Errorf("некорректная длина данных с набивкой: %d", len(data))
	}
	if mode == Zeros {
		return bytes.TrimRight(data, "\x00"), nil
	}
	n := int(data[len(data)-1])
	if n == 0 || n > bs || n > len(data) {
		return nil, fmt.Errorf("некорректная набивка: длина %d", n)
	}
	for _, b := range data[len(data)-n : len(data)-1] {
		if mode == ANSIX923 && b != 0 || mode == PKCS7 && b != byte(n) {
			return nil, fmt.Errorf("некорректная набивка: режим %d", mode)
		}
	}
	return data[:len(data)-n], nil
}

func xorBytes(a, b []byte) {
	for i := range a {
		a[i] ^= b[i]
	}
}

func counterAt(iv []byte, delta, index int) []byte {
	counter := new(big.Int).SetBytes(iv)
	offset := new(big.Int).Mul(big.NewInt(int64(delta)), big.NewInt(int64(index)))
	counter.Add(counter, offset)
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(8*len(iv)))
	counter.Mod(counter, modulus)
	return counter.FillBytes(make([]byte, len(iv)))
}

func ivFor(iv []byte, bs int) []byte {
	out := make([]byte, bs)
	copy(out, iv)
	return out
}

func (c *Context) validate(bs int) error {
	if err := validatePadding(bs, c.padding); err != nil {
		return err
	}
	if c.mode < ECB || c.mode > RandomDelta {
		return fmt.Errorf("неизвестный режим шифрования: %d", c.mode)
	}
	if c.iv != nil && len(c.iv) != bs {
		return fmt.Errorf("длина IV %d, требуется %d", len(c.iv), bs)
	}
	if c.mode == RandomDelta && len(c.modeParams) == 1 {
		if delta, ok := c.modeParams[0].(int); ok && delta > 0 && delta%2 == 1 {
			return nil
		}
		return fmt.Errorf("RandomDelta: delta должна быть положительным нечётным int")
	}
	if len(c.modeParams) != 0 {
		return fmt.Errorf("недопустимые параметры режима %d", c.mode)
	}
	return nil
}

func (c *Context) apply(data []byte, encrypt bool) ([]byte, error) {
	if c.cipher == nil {
		return nil, fmt.Errorf("не задан блочный шифр")
	}
	bs := c.cipher.BlockSize()
	if err := c.validate(bs); err != nil {
		return nil, err
	}
	if encrypt {
		padded, err := pad(data, bs, c.padding)
		if err != nil {
			return nil, err
		}
		return c.applyMode(padded, bs, true)
	}
	if len(data) == 0 || len(data)%bs != 0 {
		return nil, fmt.Errorf("длина данных %d не кратна размеру блока %d", len(data), bs)
	}
	out, err := c.applyMode(data, bs, false)
	if err != nil {
		return nil, err
	}
	return unpad(out, bs, c.padding)
}

func (c *Context) applyMode(data []byte, bs int, encrypt bool) ([]byte, error) {
	n := len(data) / bs
	if (c.mode == CTR || c.mode == RandomDelta) && n > 0 {
		if big.NewInt(int64(n-1)).BitLen() > 8*bs {
			return nil, fmt.Errorf("исчерпан период счётчика")
		}
	}
	out := make([]byte, len(data))
	iv := ivFor(c.iv, bs)
	switch c.mode {
	case ECB:
		f := c.cipher.Encrypt
		if !encrypt {
			f = c.cipher.Decrypt
		}
		parallelBlocks(len(data)/bs, func(start, end int) {
			for i := start; i < end; i++ {
				off := i * bs
				copy(out[off:off+bs], f(bytes.Clone(data[off:off+bs])))
			}
		})
	case CBC, CFB:
		if !encrypt {
			parallelBlocks(len(data)/bs, func(start, end int) {
				for i := start; i < end; i++ {
					off := i * bs
					prev := iv
					if i > 0 {
						prev = data[off-bs : off]
					}
					var res []byte
					if c.mode == CBC {
						res = c.cipher.Decrypt(bytes.Clone(data[off : off+bs]))
						xorBytes(res, prev)
					} else {
						res = c.cipher.Encrypt(bytes.Clone(prev))
						xorBytes(res, data[off:off+bs])
					}
					copy(out[off:off+bs], res)
				}
			})
			break
		}
		for off := 0; off < len(data); off += bs {
			blk := bytes.Clone(data[off : off+bs])
			if c.mode == CBC {
				xorBytes(blk, iv)
				blk = c.cipher.Encrypt(blk)
			} else {
				xorBytes(blk, c.cipher.Encrypt(bytes.Clone(iv)))
			}
			copy(out[off:off+bs], blk)
			copy(iv, blk)
		}
	case PCBC:
		for off := 0; off < len(data); off += bs {
			blk := bytes.Clone(data[off : off+bs])
			if encrypt {
				xorBytes(blk, iv)
				blk = c.cipher.Encrypt(blk)
			} else {
				blk = c.cipher.Decrypt(blk)
				xorBytes(blk, iv)
			}
			copy(out[off:off+bs], blk)
			copy(iv, data[off:off+bs])
			xorBytes(iv, blk)
		}
	case OFB:
		for off := 0; off < len(data); off += bs {
			iv = c.cipher.Encrypt(iv)
			copy(out[off:off+bs], data[off:off+bs])
			xorBytes(out[off:off+bs], iv)
		}
	case CTR, RandomDelta:
		delta := 1
		if c.mode == RandomDelta && len(c.modeParams) == 1 {
			delta = c.modeParams[0].(int)
		}
		parallelBlocks(len(data)/bs, func(start, end int) {
			for i := start; i < end; i++ {
				off := i * bs
				copy(out[off:off+bs], data[off:off+bs])
				xorBytes(out[off:off+bs], c.cipher.Encrypt(counterAt(iv, delta, i)))
			}
		})
	}
	return out, nil
}

func parallelBlocks(n int, f func(start, end int)) {
	if n == 0 {
		return
	}
	workers := min(n, runtime.GOMAXPROCS(0))
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		start := w * n / workers
		end := (w + 1) * n / workers
		wg.Add(1)
		go func() {
			defer wg.Done()
			f(start, end)
		}()
	}
	wg.Wait()
}
