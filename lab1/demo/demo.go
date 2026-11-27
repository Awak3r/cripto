package demo

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"

	"lab1/internal/deal"
	"lab1/internal/des"
	"lab1/internal/interfaces"
	cryptoctx "lab1/internal/models"
)

type algorithm struct {
	name string
	key  string
	new  func() interfaces.BlockCipher
}

var algorithms = []algorithm{
	{"DES", "8bytekey", func() interfaces.BlockCipher { return des.NewCipher() }},
	{"DEAL", "16bytekeyDEALkey", func() interfaces.BlockCipher { return deal.NewCipher() }},
}

type modeEntry struct {
	name string
	mode cryptoctx.CipherMode
}

var modes = []modeEntry{
	{"ECB", cryptoctx.ECB},
	{"CBC", cryptoctx.CBC},
	{"PCBC", cryptoctx.PCBC},
	{"CFB", cryptoctx.CFB},
	{"OFB", cryptoctx.OFB},
	{"CTR", cryptoctx.CTR},
	{"RandomDelta", cryptoctx.RandomDelta},
}

var paddings = []struct {
	name string
	mode cryptoctx.PaddingMode
}{
	{"Zeros", cryptoctx.Zeros},
	{"ANSIX923", cryptoctx.ANSIX923},
	{"PKCS7", cryptoctx.PKCS7},
	{"ISO10126", cryptoctx.ISO10126},
}

var lengths = []int{100}

func Run() error {
	var errs []error
	for _, a := range algorithms {
		phase := "байтовое демо"
		report := func(label string, err error) {
			if err != nil {
				fmt.Printf("%-30s FAIL: %v\n", label, err)
				errs = append(errs, fmt.Errorf("%s: %s: %s: %w", a.name, phase, label, err))
			} else {
				fmt.Printf("%-30s OK\n", label)
			}
		}
		fmt.Printf("\n=== %s: псевдослучайные байты ===\n", a.name)
		byteDemo(a, report)
		phase = "файловое демо"
		fmt.Printf("\n=== %s: файлы из data/ ===\n", a.name)
		if err := fileDemo(a, "data", report); err != nil {
			report("подготовка/очистка", err)
		}
	}
	return errors.Join(errs...)
}

func newContext(a algorithm, m modeEntry, padding cryptoctx.PaddingMode) *cryptoctx.Context {
	var iv []byte
	if m.mode != cryptoctx.ECB {
		iv = make([]byte, a.new().BlockSize())
		for i := range iv {
			iv[i] = byte(i + 1)
		}
	}
	var params []any
	if m.mode == cryptoctx.RandomDelta {
		params = []any{257}
	}

	return cryptoctx.NewContext(a.new, m.mode, padding, []byte(a.key), iv, params...)
}

func sample(rng *rand.Rand, n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(rng.Intn(256))
	}

	if n > 0 && data[n-1] == 0 {
		data[n-1] = 1
	}
	return data
}

func roundtripBytes(c *cryptoctx.Context, data []byte) error {
	enc := <-c.EncryptBytes(data, nil)
	if enc.Err != nil {
		return fmt.Errorf("encrypt: %w", enc.Err)
	}
	dec := <-c.DecryptBytes(enc.Data, nil)
	if dec.Err != nil {
		return fmt.Errorf("decrypt: %w", dec.Err)
	}
	if !bytes.Equal(data, dec.Data) {
		return fmt.Errorf("расшифрованные байты отличаются от исходных")
	}
	return nil
}

func byteDemo(a algorithm, report func(string, error)) {
	for _, m := range modes {
		for _, p := range paddings {
			rng := rand.New(rand.NewSource(1))
			c := newContext(a, m, p.mode)
			var err error
			for _, n := range lengths {
				if err = roundtripBytes(c, sample(rng, n)); err != nil {
					err = fmt.Errorf("длина %d: %w", n, err)
					break
				}
			}
			report(m.name+"/"+p.name, err)
		}
	}
}

func fileDemo(a algorithm, dir string, report func(string, error)) (err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("чтение %s: %w", dir, err)
	}
	var files []string
	for _, e := range entries {
		if e.Type().IsRegular() {
			files = append(files, e.Name())
		}
	}
	if len(files) == 0 {
		return fmt.Errorf("в %s нет файлов: добавьте текст, изображение, музыку или видео", dir)
	}
	out, err := os.MkdirTemp("", "lab1-demo-")
	if err != nil {
		return fmt.Errorf("создание временного каталога: %w", err)
	}
	defer func() {
		if cleanupErr := os.RemoveAll(out); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("удаление временного каталога: %w", cleanupErr))
		}
	}()

	enc := filepath.Join(out, "encrypted")
	dec := filepath.Join(out, "decrypted")
	for _, f := range files {
		for _, m := range modes {
			report(f+"/"+m.name, roundtripFile(a, filepath.Join(dir, f), enc, dec, m))
		}
	}
	return nil
}

func roundtripFile(a algorithm, src, enc, dec string, m modeEntry) error {
	c := newContext(a, m, cryptoctx.PKCS7)
	if err := <-c.EncryptFile(src, enc); err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	if err := <-c.DecryptFile(enc, dec); err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	orig, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	got, err := os.ReadFile(dec)
	if err != nil {
		return err
	}
	if !bytes.Equal(orig, got) {
		return fmt.Errorf("расшифрованный файл отличается от исходного")
	}
	return nil
}
