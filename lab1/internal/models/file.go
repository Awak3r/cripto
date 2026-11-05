package cryptoctx

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Порция округляется вниз до целого числа блоков (минимум один блок).
const fileChunkSize = 64 * 1024

func (c *Context) cryptFile(inPath, outPath string, encrypt bool) <-chan error {
	ch := make(chan error, 1)
	go func() {
		defer close(ch)
		ch <- c.processFile(inPath, outPath, encrypt)
	}()
	return ch
}

func (c *Context) processFile(inPath, outPath string, encrypt bool) (err error) {
	if c.cipher == nil {
		return fmt.Errorf("не задан блочный шифр")
	}
	bs := c.cipher.BlockSize()
	if err := c.validate(bs); err != nil {
		return err
	}
	input, err := os.Open(inPath)
	if err != nil {
		return err
	}
	inputClosed := false
	defer func() {
		if !inputClosed {
			err = errors.Join(err, input.Close())
		}
	}()

	// Не следуем символьным ссылкам при выборе прав: Rename заменяет саму
	// запись назначения, а не файл, на который она указывает.
	mode := os.FileMode(0o600)
	if info, err := os.Lstat(outPath); err == nil {
		if info.Mode().IsRegular() {
			mode = info.Mode().Perm()
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	output, err := os.CreateTemp(filepath.Dir(outPath), ".cryptoctx-*")
	if err != nil {
		return err
	}
	outputClosed, committed := false, false
	defer func() {
		if !outputClosed {
			err = errors.Join(err, output.Close())
		}
		if !committed {
			if removeErr := os.Remove(output.Name()); removeErr != nil {
				err = errors.Join(err, fmt.Errorf("удаление временного файла %q: %w", output.Name(), removeErr))
			}
		}
	}()

	if err := c.streamFile(input, output, bs, encrypt); err != nil {
		return err
	}
	// Закрытие входа до Rename позволяет обрабатывать файл на месте,
	// в том числе на платформах, запрещающих замену открытого файла.
	inputClosed = true
	if err := input.Close(); err != nil {
		return err
	}
	// Пока записывались данные, временный файл имел права 0600.
	// Перед публикацией сохраняем биты доступа обычного назначения.
	if mode != 0o600 {
		if err := output.Chmod(mode); err != nil {
			return err
		}
	}
	if err := output.Sync(); err != nil {
		return err
	}
	outputClosed = true
	if err := output.Close(); err != nil {
		return err
	}
	// Временный файл лежит в том же каталоге. На Unix Rename атомарен;
	// вне Unix os.Rename не гарантирует атомарность даже в одном каталоге.
	// При ошибке НЕ удаляем старое назначение ради повторной попытки.
	err = os.Rename(output.Name(), outPath)
	committed = err == nil
	return err
}

func (c *Context) streamFile(input io.Reader, output *os.File, bs int, encrypt bool) error {
	reader := bufio.NewReader(input)
	buffer := make([]byte, max(bs, fileChunkSize/bs*bs))
	state := c.newModeState(bs)
	var nonzeroEnd int64
	for {
		n, readErr := io.ReadFull(reader, buffer)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return readErr
		}
		final := readErr != nil
		data := buffer[:n]
		if encrypt {
			if final {
				var err error
				data, err = pad(data, bs, c.padding)
				if err != nil {
					return err
				}
			}
		} else {
			if n == 0 || n%bs != 0 {
				return fmt.Errorf("некорректная длина шифротекста: порция %d, размер блока %d", n, bs)
			}
			if !final {
				// Один байт упреждения отличает последний полный буфер
				// от промежуточного, не загружая следующий буфер целиком.
				if _, err := reader.Peek(1); err != nil {
					if err != io.EOF {
						return err
					}
					final = true
				}
			}
		}
		out, err := c.applyMode(data, bs, encrypt, state)
		if err != nil {
			return err
		}
		if !encrypt && final && c.padding != Zeros {
			last, err := unpad(out[len(out)-bs:], bs, c.padding)
			if err != nil {
				return err
			}
			out = out[:len(out)-bs+len(last)]
		}
		if n, err := output.Write(out); err != nil {
			return err
		} else if n != len(out) {
			return io.ErrShortWrite
		}
		if !encrypt && c.padding == Zeros {
			// Zeros удаляет ВСЕ конечные нули, включая несколько порций.
			// Запоминаем позицию последнего ненулевого байта, а не держим
			// потенциально неограниченный хвост в памяти.
			trimmed := bytes.TrimRight(out, "\x00")
			if len(trimmed) > 0 {
				end, err := output.Seek(0, io.SeekCurrent)
				if err != nil {
					return err
				}
				nonzeroEnd = end - int64(len(out)-len(trimmed))
			}
		}
		if final {
			if !encrypt && c.padding == Zeros {
				return output.Truncate(nonzeroEnd)
			}
			return nil
		}
	}
}
