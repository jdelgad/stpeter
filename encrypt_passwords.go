// +build encrypt_passwords

package main

import (
	"fmt"
	"github.com/jdelgad/stpeter/auth"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {

	fmt.Print("Enter password: ")
	p, err := terminal.ReadPassword(0)
	fmt.Println()

	if err != nil {
		panic("Could not obtain password")
	}

	pp, err := auth.EncryptPassword(p)
	fmt.Println(pp)
}
