package main

import (
	"github.com/nightshaders/stpeter/auth"
)

func main() {

	s := auth.SetupServerSocket("tcp://127.0.0.1:13000")
	defer s.Close()

	auth.ServiceLoginRequests(s, "passwd", "salt")
}
