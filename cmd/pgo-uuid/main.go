package main

import (
	"fmt"
	"os"

	"github.com/prothegee/pgo/pkg/pgo"
)

const (
	DEFAULT_OUTPUT = "nothing to generate; only accept `v1` `v4` & `v7` as the arg"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println(DEFAULT_OUTPUT)
		return
	}

	arg := os.Args[1]
	if arg != "v1" && arg != "v4" && arg != "v7" {
		fmt.Println(DEFAULT_OUTPUT)
		return
	}

	if arg == "v1" {
		res, _ := pgo.UUIDv1()
		fmt.Println(res)
	}
	if arg == "v4" {
		res, _ := pgo.UUIDv4()
		fmt.Println(res)
	}
	if arg == "v7" {
		res, _ := pgo.UUIDv7()
		fmt.Println(res)
	}
}
