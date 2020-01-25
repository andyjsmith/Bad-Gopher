# Bad Gopher

Proof-of-concept ransomware written in Go

## Instructions
* Install all dependencies: `go get -d ./...`
* Generate an RSA public-private keypair by running the rsa_keygen.go program in the keygen directory (`go run keygen/rsa_keygen.go`).
* Replace the publicKey variable in embeddedFiles.go with the contents of your pub.pem
* Build the program to distribute: `go build`
* Send the executable to your victim
* After the victim runs the program, their files will be encrypted and they will have a BAD_GOPHER.txt file in their home directory
* To generate the decryption key, the victim sends the BAD_GOPHER.txt file to the attacker. Run the decryption program, specifying the private key and input file (`go run key_decrypt/key_decrypt.go --key priv.pem --input BAD_GOPHER.txt`)
* Send the generated BAD_GOPHER_DECRYPT_YYYY_MM_DD file back to the victim
* The victim can drag the decryption file onto the BAD_GOPHER executable in their home directory to start decryption, or run the file and specify the path to the decryption file.