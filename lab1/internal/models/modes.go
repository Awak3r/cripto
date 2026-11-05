package cryptoctx

import (
	"bytes"
	"fmt"
	"math/bits"
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

func addDelta(b []byte, d int) {
	carry := uint(d)
	for i := len(b) - 1; i >= 0 && carry != 0; i-- {
		v := uint(b[i]) + (carry & 255)
		b[i] = byte(v)
		carry = (carry >> 8) + (v >> 8)
	}
}

func counterAt(iv []byte, delta, index int) []byte {
	out := bytes.Clone(iv)
	hi, lo := bits.Mul(uint(delta), uint(index))
	carry := uint(0)
	for i := len(out) - 1; i >= 0; i-- {
		carry += uint(out[i]) + (lo & 255)
		out[i] = byte(carry)
		carry >>= 8
		lo = lo>>8 | hi<<(bits.UintSize-8)
		hi >>= 8
	}
	return out
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
	state := c.newModeState(bs)
	if encrypt {
		padded, err := pad(data, bs, c.padding)
		if err != nil {
			return nil, err
		}
		return c.applyMode(padded, bs, true, state)
	}
	if len(data) == 0 || len(data)%bs != 0 {
		return nil, fmt.Errorf("длина данных %d не кратна размеру блока %d", len(data), bs)
	}
	out, err := c.applyMode(data, bs, false, state)
	if err != nil {
		return nil, err
	}
	return unpad(out, bs, c.padding)
}

// Состояние принадлежит одной операции, а не Context: параллельные операции
// не должны менять IV и счётчик друг друга.
type modeState struct {
	iv        []byte
	used      []byte
	exhausted bool
}

func (c *Context) newModeState(bs int) *modeState {
	s := &modeState{iv: ivFor(c.iv, bs)}
	if c.mode == CTR || c.mode == RandomDelta {
		s.used = make([]byte, bs)
	}
	return s
}

// Нечётный шаг имеет период 2^(8*bs). Считаем блоки в bs байтах,
// отдельно представляя ровно полный период: ни сдвигов на 8*bs, ни
// переполнения машинного счётчика на длинных потоках здесь нет.
func (s *modeState) reserve(n int) error {
	if n == 0 {
		return nil
	}
	if s.exhausted {
		return fmt.Errorf("исчерпан период счётчика CTR/RandomDelta")
	}
	next := bytes.Clone(s.used)
	carry := uint(n)
	for i := len(next) - 1; i >= 0; i-- {
		v := uint(next[i]) + (carry & 255)
		next[i] = byte(v)
		carry = (carry >> 8) + (v >> 8)
	}
	if carry != 0 {
		if carry != 1 || len(bytes.TrimLeft(next, "\x00")) != 0 {
			return fmt.Errorf("исчерпан период счётчика CTR/RandomDelta")
		}
		s.exhausted = true
	}
	s.used = next
	return nil
}

func (c *Context) applyMode(data []byte, bs int, encrypt bool, state *modeState) ([]byte, error) {
	if c.mode == CTR || c.mode == RandomDelta {
		if err := state.reserve(len(data) / bs); err != nil {
			return nil, err
		}
	}
	out := make([]byte, len(data))
	iv := state.iv
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
			if len(data) > 0 {
				copy(iv, data[len(data)-bs:])
			}
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
			counter := counterAt(iv, delta, start)
			for i := start; i < end; i++ {
				off := i * bs
				copy(out[off:off+bs], data[off:off+bs])
				xorBytes(out[off:off+bs], c.cipher.Encrypt(bytes.Clone(counter)))
				addDelta(counter, delta)
			}
		})
		iv = counterAt(iv, delta, len(data)/bs)
	}
	state.iv = iv
	return out, nil
}

func parallelBlocks(n int, f func(start, end int)) {
	workers := min(n, runtime.GOMAXPROCS(0))
	if workers <= 1 {
		if n > 0 {
			f(0, n)
		}
		return
	}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		start := n/workers*w + min(w, n%workers)
		end := start + n/workers
		if w < n%workers {
			end++
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			f(start, end)
		}()
	}
	wg.Wait()
}
