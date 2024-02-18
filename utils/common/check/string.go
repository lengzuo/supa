package check

import (
	"fmt"
	"net/mail"
	"strings"
)

func Email(email string) error {
	if strings.TrimSpace(email) == "" {
		return fmt.Errorf("email cant be blank")
	}
	_, err := mail.ParseAddress(email)
	return err
}

func Empty(input string) bool {
	if strings.TrimSpace(input) == "" {
		return true
	}
	return false
}
