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
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Ошибка генерации RSA ключей:", err)
	}
	publicKey = &privateKey.PublicKey
}

func rsaEncrypt(data []byte) []byte {
	fmt.Println("Шифрование RSA")
	initRSAKeys()

	label := []byte("")
	hash := sha256.New()

	encryptedData, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, data, label)
	if err != nil {
		fmt.Println("Ошибка шифрования RSA:", err)
	}
	return encryptedData
}

func rsaDecrypt(data []byte) []byte {
	fmt.Println("Расшифрование RSA")
	label := []byte("")
	hash := sha256.New()

	decryptedData, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, data, label)
	if err != nil {
		fmt.Println("Ошибка расшифрования RSA:", err)
	}
	return decryptedData
}
