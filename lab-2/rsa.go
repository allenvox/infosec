package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey

func initRSAKeys() {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048) // private key
	if err != nil {
		fmt.Println("Ошибка генерации RSA ключей:", err)
	}
	publicKey = &privateKey.PublicKey // get public key from private key
}

func rsaEncrypt(data []byte) []byte {
	initRSAKeys()
	label := []byte("") // for OAEP
	hash := sha256.New()
	encryptedData, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, data, label)
	if err != nil {
		fmt.Println("Ошибка шифрования RSA:", err)
	}
	return encryptedData
}

func rsaDecrypt(data []byte) []byte {
	label := []byte("")
	hash := sha256.New()
	decryptedData, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, data, label)
	if err != nil {
		fmt.Println("Ошибка расшифрования RSA:", err)
	}
	return decryptedData
}
