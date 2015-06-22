package authenticator

import (
	"errors"
	"github.com/golang/protobuf/proto"
	"github.com/jdelgad/goforum/protos"
	"github.com/jdelgad/goforum/transport"
)

func SetupServerSocket(address string) *transport.ServerSocket {
	s := transport.NewServerSocket()
	s.Open()
	s.Connect(address)
	return s
}

func SetupClientSocket(address string) *transport.ClientSocket {
	s := transport.NewClientSocket()
	s.Open()
	s.Connect(address)
	return s
}

func CreateLoginReply() *protos.LoginReply {
	return &protos.LoginReply{}
}

func CreateLoginRequest() *protos.Login {
	return &protos.Login{}
}

func parseLoginRequest(b []byte) (*protos.Login, error) {
	login := CreateLoginRequest()
	err := proto.Unmarshal(b, login)

	if err != nil {
		return login, errors.New("could not parse login protobuf")
	}

	return login, nil
}

func isValidLogin(l protos.Login) (bool, error) {
	return IsValidUserPass(*l.Username, l.Password)
}

func authFailure(r *protos.LoginReply) {
	authorization := protos.LoginReply_FAILED
	r.Authorized = &authorization
	sid := "-1"
	r.SessionID = &sid
}

func authSuccess(r *protos.LoginReply) {
	authorization := protos.LoginReply_SUCCESSFUL
	r.Authorized = &authorization
	sid := "1"
	r.SessionID = &sid
}

func SendLoginReply(r *protos.LoginReply, s *transport.ServerSocket) error {
	b, err := proto.Marshal(r)

	if err != nil {
		return errors.New("could not serialize login reply")
	}

	return s.Send(b)
}

func SendLoginRequest(r *protos.Login, s *transport.ClientSocket) error {
	b, err := proto.Marshal(r)

	if err != nil {
		return errors.New("could not serialize login request")
	}

	return s.Send(b)
}

func ServiceLoginReply(s *transport.ClientSocket) (bool, error) {
	b, err := s.Receive()

	if err != nil {
		return false, errors.New("could not receive login reply")
	}

	rep := CreateLoginReply()
	err = proto.Unmarshal(b, rep)

	if err != nil {
		return false, errors.New("could not deserialize login reply")
	}

	success := false
	if *rep.Authorized == protos.LoginReply_SUCCESSFUL {
		success = true
	}
	return success, nil
}

func ServiceLoginRequests(s *transport.ServerSocket) error {
	for {
		b, err := s.Receive()

		if err != nil {
			return errors.New("could not receive login request")
		}

		l, err := parseLoginRequest(b)

		r := CreateLoginReply()
		if err != nil {
			authFailure(r)
		} else {

			v, err := isValidLogin(*l)

			if err != nil {
				return errors.New("cannot determine if username/pass is valid")
			}

			if v {
				authSuccess(r)
			} else {
				authFailure(r)
			}
		}

		if err := SendLoginReply(r, s); err != nil {
			return errors.New("Could not send login reply")
		}
	}
}
