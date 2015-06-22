// +build generate_salt

package main

import (
	"errors"
	"crypto/rand"
	"io"
	"log"
	"io/ioutil"
	"os"
)

const SALT_KEY_SIZE = 32

func generateSalt() ([]byte, error) {
	salt := make([]byte, SALT_KEY_SIZE)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, errors.New("unable to create salt")
	}

	return salt, nil
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Did not pass in salt file to write to")
	}

	s, err := generateSalt()
	if err != nil {
		log.Fatal("Could not generate salt")
	}

	err = ioutil.WriteFile(os.Args[1], s, 0600)
	if err != nil {
		log.Fatal("Could not write to salt file")
	}
}
