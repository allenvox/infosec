package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
)

// Генерация ключей для ГОСТ на эллиптической кривой
func generateGostKeys() (*ecdsa.PrivateKey, error) {
	// Используем кривую P-256 (эквивалент ГОСТ)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Подписание сообщения (хэша файла)
func gostSign(hash []byte, privateKey *ecdsa.PrivateKey) (*big.Int, *big.Int, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		return nil, nil, err
	}
	return r, s, nil
}

// Проверка подписи
func gostVerify(hash []byte, r, s *big.Int, publicKey *ecdsa.PublicKey) bool {
	return ecdsa.Verify(publicKey, hash, r, s)
}

// Сохранение приватного ключа в файл
func saveGostPrivateKey(filename string, privateKey *ecdsa.PrivateKey) error {
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return err
}

// Сохранение публичного ключа в файл
func saveGostPublicKey(filename string, publicKey *ecdsa.PublicKey) error {
	keyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{Type: "PUBLIC KEY", Bytes: keyBytes})
	return err
}

/* Usage

// Генерация ключей ГОСТ (ECDSA)
	privateKey, err := generateGostKeys()
	if err != nil {
		fmt.Printf("Ошибка генерации ключей: %v\n", err)
		return
	}

	// Подписание хэша файла
	r, s, err := gostSign(hash, privateKey)
	if err != nil {
		fmt.Printf("Ошибка при подписании: %v\n", err)
		return
	}
	fmt.Printf("Подпись: r = %s, s = %s\n", r.String(), s.String())

	// Проверка подписи
	valid := gostVerify(hash, r, s, &privateKey.PublicKey)
	if valid {
		fmt.Println("Подпись корректна!")
	} else {
		fmt.Println("Подпись некорректна!")
	}

*/
