package auth

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestBadCSVPasswordFile(t *testing.T) {
	_, err := getUserPasswordList("test_files/badcsv")
	assert.Error(t, err)
}

func TestPasswordFile(t *testing.T) {
	users, err := getUserPasswordList("test_files/passwd")
	assert.Len(t, users, 2)
	assert.NoError(t, err)
}

func TestInvalidPasswordFile(t *testing.T) {
	users, err := getUserPasswordList("test_files/invalidpasswd")
	assert.Len(t, users, 2)
	assert.NoError(t, err)
}

func TestGetInvalidUserPassword(t *testing.T) {
	p, err := getPassword("nonuser", "test_files/passwd")
	assert.Empty(t, p)
	assert.Error(t, err)
}

func TestPasswordFileExistsCantRead(t *testing.T) {
	f, err := os.Create("test_files/badpasswd")
	assert.NoError(t, err)

	f.Chmod(0200)
	_, err = getUserPasswordList("test_files/badpasswd")

	assert.Error(t, err)
	os.Remove("test_files/badpasswd")
}

func TestPasswordFailureNoUser(t *testing.T) {
	v, err := IsValidUserPass("nouser", []byte("testing"), "test_files/passwd", "test_files/salt")
	assert.False(t, v)
	assert.Error(t, err)
}

func TestPasswordFailure(t *testing.T) {
	v, err := IsValidUserPass("user", []byte("testing"), "test_files/passwd", "test_files/salt")
	assert.False(t, v)
	assert.Error(t, err)
}

func TestPasswordSuccess(t *testing.T) {
	//v, err := IsValidUserPass("jdelgad", []byte("pass"))
	//assert.True(t, v)
	//assert.NoError(t, err)
}

func TestUsernameFailure(t *testing.T) {
	v, err := IsRegisteredUser("fakeUser", "test_files/passwd")
	assert.False(t, v)
	assert.NoError(t, err)
}

func TestUsernameSuccess(t *testing.T) {
	v, err := IsRegisteredUser("jdelgad", "test_files/passwd")
	assert.True(t, v)
	assert.NoError(t, err)
}

func TestPasswordFileDoesNotExist(t *testing.T) {
	users, err := getUserPasswordList("test_files/fakePasswd")
	assert.Nil(t, users)
	assert.Error(t, err)
}

func TestBlankPasswordFile(t *testing.T) {
	users, err := getUserPasswordList("test_files/blankPasswd")
	assert.Empty(t, users)
	assert.NoError(t, err)
}

func TestOpenPasswordFile(t *testing.T) {
	users, err := getUserPasswordList("test_files/passwd")
	assert.NotEmpty(t, users)
	assert.Equal(t, len(users), 2)
	assert.NoError(t, err)

	v, ok := users["jdelgad"]
	assert.NotNil(t, ok)
	assert.Equal(t, v.Username, "jdelgad")
	assert.Equal(t, v.Password, []byte("pass"))
	assert.Equal(t, v.Role, "Admin")
}

func TestAuthenticate(t *testing.T) {
	users, err := getUserPasswordList("test_files/passwd")
	assert.NoError(t, err)

	for name, user := range users {
		_, ok := OpenSession(name, user.Password, users)
		assert.Nil(t, ok)
	}

	_, ok := OpenSession("foo", []byte("bar"), users)
	assert.NotNil(t, ok)
}

func TestRegularUser(t *testing.T) {
	users, err := getUserPasswordList("test_files/passwd")
	assert.NoError(t, err)

	v, err := IsRegularUser("jdelgad", users)
	assert.False(t, v)
	assert.NoError(t, err)

	v, err = IsRegularUser("newUser", users)
	assert.True(t, v)
	assert.NoError(t, err)

	v, err = IsRegularUser("noSuchUser", users)
	assert.False(t, v)
	assert.Error(t, err)
}

func TestAdminUser(t *testing.T) {
	users, err := getUserPasswordList("test_files/passwd")
	assert.NoError(t, err)

	v, err := IsAdminUser("jdelgad", users)
	assert.True(t, v)
	assert.NoError(t, err)

	v, err = IsAdminUser("newUser", users)
	assert.False(t, v)
	assert.NoError(t, err)

	v, err = IsAdminUser("badUser", users)
	assert.False(t, v)
	assert.Error(t, err)
}

func TestIsLoggedIn(t *testing.T) {
	users, err := getUserPasswordList("test_files/passwd")
	assert.NoError(t, err)

	session, err := OpenSession("jdelgad", []byte("pass"), users)
	v := IsLoggedIn("jdelgad", session)
	assert.True(t, v)
	assert.NoError(t, err)

	session, err = OpenSession("newUser", []byte("pass2"), users)
	v = IsLoggedIn("newUser", session)
	assert.True(t, v)
	assert.NoError(t, err)

	v = IsLoggedIn("jdelgad", session)
	assert.False(t, v)
	assert.NoError(t, err)
}

func TestCloseSessionOnBadPassword(t *testing.T) {
	users, err := getUserPasswordList("test_files/passwd")
	assert.NoError(t, err)
	s, err := OpenSession("jdelgad", []byte("badpass"), users)
	assert.NoError(t, err)
	v := IsLoggedIn("jdelgad", s)
	assert.False(t, v)
}

func TestCreateUser(t *testing.T) {
	v, err := IsValidNewUsername("newestUser", "test_files/passwd")
	assert.True(t, v)
	assert.NoError(t, err)

	v, err = IsValidNewUsername("jdelgad", "test_files/passwd")
	assert.False(t, v)
	assert.Error(t, err)
}

func TestRegisterUser(t *testing.T) {
	RegisterUser("newestUser", []byte("password"), "test_files/passwd", "test_files/salt")

	v, err := IsRegisteredUser("newestUser", "test_files/passwd")

	assert.True(t, v)
	assert.NoError(t, err)
}

func TestDeleteUser(t *testing.T) {
	err := RegisterUser("newestUser", []byte("pass3"), "test_files/passwd", "test_files/salt")
	assert.NoError(t, err)

	err = DeleteUser("newestUser", "test_files/passwd")
	assert.NoError(t, err)

	users, err := getUserPasswordList("test_files/passwd")
	assert.NotNil(t, users)
	assert.NoError(t, err)

	_, ok := users["newestUser"]
	assert.False(t, ok)
}

func TestEncryptPassword(t *testing.T) {
	p, err := EncryptPassword([]byte("testing"), "test_files/salt")
	assert.NoError(t, err)
	assert.NotNil(t, p)
}