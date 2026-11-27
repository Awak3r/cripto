package cryptoctx

import "os"

func (c *Context) cryptFile(inPath, outPath string, encrypt bool) <-chan error {
	ch := make(chan error, 1)
	go func() {
		defer close(ch)
		ch <- c.processFile(inPath, outPath, encrypt)
	}()
	return ch
}

func (c *Context) processFile(inPath, outPath string, encrypt bool) error {
	data, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	out, err := c.apply(data, encrypt)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, out, 0600)
}
