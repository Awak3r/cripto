package main

import (
	"fmt"
	"os"

	"lab1/demo"
)

func main() {
	if err := demo.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
