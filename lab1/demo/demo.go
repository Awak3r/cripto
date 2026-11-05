package demo

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sync"

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

var lengths = []int{0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 100, 4096}

func Run() error {
	var errs []error
	printResult := func(label string, err error) {
		if err != nil {
			fmt.Printf("%-30s FAIL: %v\n", label, err)
		} else {
			fmt.Printf("%-30s OK\n", label)
		}
	}
	for _, a := range algorithms {
		fmt.Printf("\n=== %s: псевдослучайные байты ===\n", a.name)
		if err := byteDemo(a, printResult); err != nil {
			errs = append(errs, fmt.Errorf("%s: байтовое демо: %w", a.name, err))
		}
		fmt.Printf("\n=== %s: файлы из data/ ===\n", a.name)
		if err := fileDemo(a, "data", printResult); err != nil {
			errs = append(errs, fmt.Errorf("%s: файловое демо: %w", a.name, err))
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

type demoResult struct {
	label string
	err   error
}

func reportResults(results []demoResult, report func(string, error)) error {
	var errs []error
	for _, r := range results {
		report(r.label, r.err)
		if r.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.label, r.err))
		}
	}
	return errors.Join(errs...)
}

func byteDemo(a algorithm, report func(string, error)) error {
	var results []demoResult
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
			results = append(results, demoResult{m.name + "/" + p.name, err})
		}
	}
	return reportResults(results, report)
}

func fileDemo(a algorithm, dir string, report func(string, error)) error {
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
	out := filepath.Join(dir, "enc", a.name)
	if err := os.MkdirAll(out, 0o755); err != nil {
		return fmt.Errorf("создание %s: %w", out, err)
	}

	results := make([]demoResult, len(files)*len(modes))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range min(runtime.GOMAXPROCS(0), len(results)) {
		wg.Go(func() {
			for i := range jobs {
				f, m := files[i/len(modes)], modes[i%len(modes)]
				results[i] = demoResult{f + "/" + m.name, roundtripFile(a, dir, out, f, m)}
			}
		})
	}
	for i := range results {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return reportResults(results, report)
}

func roundtripFile(a algorithm, dir, out, f string, m modeEntry) error {
	src := filepath.Join(dir, f)
	enc := filepath.Join(out, f+"."+m.name+".enc")
	dec := filepath.Join(out, f+"."+m.name+".dec")
	c := newContext(a, m, cryptoctx.PKCS7)
	if err := <-c.EncryptFile(src, enc); err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	if err := <-c.DecryptFile(enc, dec); err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	orig, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("открытие исходного файла: %w", err)
	}
	defer orig.Close()
	got, err := os.Open(dec)
	if err != nil {
		return fmt.Errorf("открытие расшифрованного файла: %w", err)
	}
	defer got.Close()

	var origBuf, gotBuf [32 * 1024]byte
	for {
		nOrig, errOrig := io.ReadFull(orig, origBuf[:])
		if errOrig != nil && errOrig != io.EOF && errOrig != io.ErrUnexpectedEOF {
			return fmt.Errorf("чтение исходного файла: %w", errOrig)
		}
		nGot, errGot := io.ReadFull(got, gotBuf[:])
		if errGot != nil && errGot != io.EOF && errGot != io.ErrUnexpectedEOF {
			return fmt.Errorf("чтение расшифрованного файла: %w", errGot)
		}
		if !bytes.Equal(origBuf[:nOrig], gotBuf[:nGot]) {
			return fmt.Errorf("расшифрованный файл отличается от исходного")
		}
		if errOrig != nil && errGot != nil {
			return nil
		}
	}
}
