package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

// Подпись файла
func rsaSign(hash []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// Проверка подписи
func rsaVerify(hash []byte, signature []byte, publicKey *rsa.PublicKey) error {
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash, signature)
	if err != nil {
		return err
	}
	return nil
}

// Генерация ключей RSA
func generateRSAKeys(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Сохранение приватного ключа в файл
func saveRSAPrivateKey(filename string, privateKey *rsa.PrivateKey) error {
	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
}

// Сохранение публичного ключа в файл
func saveRSAPublicKey(filename string, publicKey *rsa.PublicKey) error {
	keyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{Type: "PUBLIC KEY", Bytes: keyBytes})
}

// Загрузка приватного ключа из файла
func loadRSAPrivateKey(filename string) (*rsa.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("неправильный формат ключа")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// Загрузка публичного ключа из файла
func loadRSAPublicKey(filename string) (*rsa.PublicKey, error) {
	keyBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("неправильный формат ключа")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("неправильный тип публичного ключа")
	}
	return rsaPubKey, nil
}

/* Usage

// 2. Генерация ключей RSA
	privateKey, err := generateRSAKeys(2048)
	if err != nil {
		fmt.Printf("Ошибка генерации ключей: %v\n", err)
		return
	}

	// 3. Сохранение ключей в файлы
	err = saveRSAPrivateKey("private.pem", privateKey)
	if err != nil {
		fmt.Printf("Ошибка сохранения приватного ключа: %v\n", err)
		return
	}

	err = saveRSAPublicKey("public.pem", &privateKey.PublicKey)
	if err != nil {
		fmt.Printf("Ошибка сохранения публичного ключа: %v\n", err)
		return
	}

	// 4. Подписание файла
	signature, err := rsaSign(hash, privateKey)
	if err != nil {
		fmt.Printf("Ошибка при подписании файла: %v\n", err)
		return
	}
	fmt.Printf("Подпись файла: %x\n", signature)

	// 5. Проверка подписи
	publicKey, err := loadRSAPublicKey("public.pem")
	if err != nil {
		fmt.Printf("Ошибка загрузки публичного ключа: %v\n", err)
		return
	}

	err = rsaVerify(hash, signature, publicKey)
	if err != nil {
		fmt.Printf("Подпись некорректна: %v\n", err)
	} else {
		fmt.Println("Подпись корректна!")
	}

*/
