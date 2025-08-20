package main

import (
	"github.com/chet-wynn-cookieai/oauth2client/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		panic(err)
	}
}
