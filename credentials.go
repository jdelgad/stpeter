package authenticator

import (
	"encoding/csv"
	"errors"
	"golang.org/x/crypto/scrypt"
	"io/ioutil"
	"os"
	"bytes"
)

type User struct {
	Username string
	Role     string
	Password []byte
}

type Session struct {
	user   User
	active bool
}

// returns whether the given file exists or not
func isFile(path string) bool {
	_, err := os.Stat(path)

	if err == nil {
		return true
	}

	return false
}

func getUserPasswordList(file string) (map[string]User, error) {
	if !isFile(file) {
		return nil, errors.New("password file does not exist")
	}

	f, err := os.Open(file)

	if err != nil {
		return nil, errors.New("could not open password file")
	}

	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1

	rows, err := reader.ReadAll()

	if err != nil {
		return nil, errors.New("could not read password file")
	}

	var userPass = make(map[string]User)

	for _, each := range rows {
		var username, password, role string
		if len(each) == 3 {
			username, password, role = each[0], each[1], each[2]
		} else if len(each) == 2 {
			username, password, role = each[0], each[1], "Regular"
		} else {
			continue
		}

		userInfo := User{
			Username: username,
			Password: []byte(password),
			Role: role}
		userPass[username] = userInfo
	}

	return userPass, nil
}

func IsRegisteredUser(u string) (bool, error) {
	users, err := getUserPasswordList("passwd")

	if err != nil {
		return false, errors.New("could not read user password list")
	}

	_, ok := users[u]

	return ok, nil
}

func IsValidUserPass(u string, p []byte) (bool, error) {
	r, err := IsRegisteredUser(u)

	if err != nil {
		return false, errors.New("user is not registered")
	}

	pass, err := getPassword(u)

	if err != nil {
		return false, errors.New("password does not exist")
	}

	enc_pass, err := EncryptPassword(p)
	if err != nil {
		return false, errors.New("password could not be encrypted")
	}

	return r && bytes.Equal(enc_pass, pass), nil
}

func EncryptPassword(p []byte) ([]byte, error) {
	s, err := getSalt("salt")
	if err != nil {
		return nil, errors.New("could not read salt file")
	}

	return scrypt.Key(p, s, 16384, 8, 1, 32)
}

func getSalt(f string) ([]byte, error) {
	return ioutil.ReadFile(f)
}

func getPassword(u string) ([]byte, error) {
	users, err := getUserPasswordList("passwd")

	if err != nil {
		return nil, errors.New("could not retrieve user password")
	}

	user, ok := users[u]
	if !ok {
		return nil, errors.New("user does not exist")
	}

	return user.Password, nil
}

func OpenSession(name string, pass []byte, users map[string]User) (Session, error) {
	user, ok := users[name]
	if !ok {
		return Session{}, errors.New("user does not exist")
	}

	var session Session
	if bytes.Equal(users[name].Password, pass) {
		session = Session{user: user, active: true}
	} else {
		session = Session{user: user, active: false}
	}

	return session, nil
}

func IsRegularUser(name string, users map[string]User) (bool, error) {
	user, ok := users[name]

	if !ok {
		return false, errors.New("user not found")
	}

	return user.Role == "Regular", nil
}

func IsAdminUser(name string, users map[string]User) (bool, error) {
	user, ok := users[name]

	if !ok {
		return false, errors.New("user not found")
	}

	return user.Role == "Admin", nil
}

func IsLoggedIn(name string, session Session) bool {
	return session.user.Username == name && session.active
}

func IsValidNewUsername(name string) (bool, error) {
	users, err := getUserPasswordList("passwd")

	if err != nil {
		return false, errors.New("could not get list of registered users")
	}

	_, ok := users[name]

	if ok {
		return false, errors.New("username already taken")
	}

	return true, nil
}

func RegisterUser(name string, pw []byte) error {
	users, err := getUserPasswordList("passwd")
	if err != nil {
		return errors.New("could not read user list")
	}

	enc_pass, err := EncryptPassword(pw)
	if err != nil {
		return errors.New("could not encrypt user password")
	}

	user := User{
		Username: name,
		Password: enc_pass,
		Role:     "Regular"}

	users[name] = user

	err = updateUserList(users)
	return err
}

func updateUserList(users map[string]User) error {
	err := os.Remove("passwd")

	if err != nil {
		return errors.New("could not remove password file")
	}

	f, err := os.OpenFile("passwd", os.O_WRONLY|os.O_CREATE, 0600)

	if err != nil {
		return errors.New("could not open password file")
	}
	defer f.Close()

	w := csv.NewWriter(f)

	records := make([][]string, 0)
	for _, info := range users {
		record := make([]string, 0)
		record = append(record, info.Username)
		record = append(record, string(info.Password))
		record = append(record, info.Role)
		records = append(records, record)
	}

	err = w.WriteAll(records)

	if err != nil {
		return errors.New("could not write password file")
	}

	return nil
}

func DeleteUser(user string) error {
	users, err := getUserPasswordList("passwd")

	if err != nil {
		return errors.New("could not open user list")
	}

	_, ok := users[user]

	if !ok {
		return errors.New("cannot erase user. does not exist")
	}

	delete(users, user)

	err = updateUserList(users)

	return err
}
