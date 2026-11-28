package cryptoctx

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func (c *Context) cryptFile(inPath, outPath string, encrypt bool) <-chan error {
	ch := make(chan error, 1)
	go func() {
		defer close(ch)
		ch <- c.processFile(inPath, outPath, encrypt)
	}()
	return ch
}

func (c *Context) processFile(inPath, outPath string, encrypt bool) error {
	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.CreateTemp(filepath.Dir(outPath), ".crypto-*")
	if err != nil {
		return err
	}
	defer os.Remove(out.Name())
	defer out.Close()

	if err := c.processStream(in, out, encrypt); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := in.Close(); err != nil {
		return err
	}
	return os.Rename(out.Name(), outPath)
}

func (c *Context) processStream(in io.Reader, out *os.File, encrypt bool) error {
	if c.cipher == nil {
		return fmt.Errorf("не задан блочный шифр")
	}
	bs := c.cipher.BlockSize()
	if err := c.validate(bs); err != nil {
		return err
	}

	state := *c
	state.iv = ivFor(c.iv, bs)
	reader := bufio.NewReader(in)
	buf := make([]byte, max(bs, 64*1024/bs*bs))
	var written, lastNonZero int64
	var processed uint64

	for {
		n, err := io.ReadFull(reader, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		last := err != nil
		data := buf[:n]

		if encrypt {
			if last {
				data, err = pad(data, bs, c.padding)
				if err != nil {
					return err
				}
			}
		} else {
			if n == 0 || n%bs != 0 {
				return fmt.Errorf("некорректная длина шифртекста")
			}
			if !last {
				_, err = reader.Peek(1)
				if err != nil && err != io.EOF {
					return err
				}
				last = err == io.EOF
			}
		}

		if (c.mode == CTR || c.mode == RandomDelta) && bs < 8 {
			processed += uint64(len(data) / bs)
			if processed > uint64(1)<<(8*bs) {
				return fmt.Errorf("исчерпан период счётчика")
			}
		}
		result, err := state.applyChunk(data, bs, encrypt)
		if err != nil {
			return err
		}

		if !encrypt {
			if c.padding == Zeros {
				if n := len(bytes.TrimRight(result, "\x00")); n > 0 {
					lastNonZero = written + int64(n)
				}
				written += int64(len(result))
			} else if last {
				result, err = unpad(result, bs, c.padding)
				if err != nil {
					return err
				}
			}
		}
		if _, err := out.Write(result); err != nil {
			return err
		}
		if last {
			if !encrypt && c.padding == Zeros {
				return out.Truncate(lastNonZero)
			}
			return nil
		}
	}
}

func (c *Context) applyChunk(data []byte, bs int, encrypt bool) ([]byte, error) {
	out, err := c.applyMode(data, bs, encrypt)
	if err != nil {
		return nil, err
	}
	last := len(data) - bs
	switch c.mode {
	case CBC, CFB:
		if encrypt {
			copy(c.iv, out[last:])
		} else {
			copy(c.iv, data[last:])
		}
	case PCBC, OFB:
		copy(c.iv, data[last:])
		xorBytes(c.iv, out[last:])
	case CTR, RandomDelta:
		delta := 1
		if c.mode == RandomDelta && len(c.modeParams) == 1 {
			delta = c.modeParams[0].(int)
		}
		c.iv = counterAt(c.iv, delta, len(data)/bs)
	}
	return out, nil
}
