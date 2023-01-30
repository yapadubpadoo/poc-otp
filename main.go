package main

import (
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"bufio"
	"encoding/base32"
	"fmt"
	"os"
	"time"
)

var totpOptions totp.ValidateOpts = totp.ValidateOpts{
	Period:    30,
	Skew:      1,
	Digits:    otp.DigitsSix,
	Algorithm: otp.AlgorithmSHA512,
}

func main() {
	// Use ref. code and the phone number as a secret
	refCode := "AQ82"
	phoneNo := "1887126"
	payload := fmt.Sprintf("%s%s", refCode, phoneNo)
	secret := SecretFrom(payload)
	passcode := GeneratePassCode(payload,secret)
	
	// Now Validate that the user's successfully added the passcode.
	fmt.Printf("OTP: %s\n\n", passcode)
	userPasscode := promptForPasscode()
	
	valid, _ := totp.ValidateCustom(userPasscode, secret, time.Now(), totpOptions)
	if valid {
		println("\n\nValid passcode!")
		os.Exit(0)
	} else {
		println("Invalid passcode!")
		os.Exit(1)
	}
}

func promptForPasscode() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Passcode: ")
	text, _ := reader.ReadString('\n')
	return text
}

func SecretFrom(payload string) string {
	return base32.StdEncoding.EncodeToString([]byte(payload))
}

func GeneratePassCode(payload string, secret string) string {
        passcode, err := totp.GenerateCodeCustom(secret, time.Now(), totpOptions)
        if err != nil {
                panic(err)
        }
        return passcode
}

