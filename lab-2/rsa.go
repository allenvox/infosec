package main

import (
	"crypto/rand"
	"io/ioutil"
	"math/big"
)

func generatePrime(bitLen int) (*big.Int, error) {
	prime, err := rand.Prime(rand.Reader, bitLen)
	if err != nil {
		return nil, err
	}
	return prime, nil
}

func modInverse(a, m *big.Int) *big.Int {
	g := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)
	g.GCD(x, y, a, m) // Алгоритм Евклида для нахождения НОД и коэффициентов
	if g.Cmp(big.NewInt(1)) != 0 {
		return nil // Инверсии не существует
	}
	return x.Mod(x, m)
}

func generateRSAKeys(bitLen int) (*big.Int, *big.Int, *big.Int, *big.Int) {
	p, _ := generatePrime(bitLen)
	q, _ := generatePrime(bitLen)
	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
	e := big.NewInt(65537)
	d := modInverse(e, phi)
	return e, d, n, phi
}

// c = m^e mod n
func encryptRSA(message *big.Int, e *big.Int, n *big.Int) *big.Int {
	return new(big.Int).Exp(message, e, n)
}

// m = c^d mod n
func decryptRSA(ciphertext *big.Int, d *big.Int, n *big.Int) *big.Int {
	return new(big.Int).Exp(ciphertext, d, n)
}

func rsaEncrypt(data []byte, e *big.Int, n *big.Int) []byte {
	var encryptedData []byte
	blockSize := n.BitLen() / 8 // Размер блока для шифрования
	// Разбиваем данные на блоки и шифруем каждый блок
	for i := 0; i < len(data); i += blockSize {
		block := data[i:min(i+blockSize, len(data))]
		// Преобразуем блок в число
		blockInt := new(big.Int).SetBytes(block)
		// Шифруем блок
		encryptedBlock := encryptRSA(blockInt, e, n)
		// Добавляем зашифрованные данные
		encryptedData = append(encryptedData, encryptedBlock.Bytes()...)
	}
	return encryptedData
}

func rsaDecrypt(data []byte, d *big.Int, n *big.Int) []byte {
	var decryptedData []byte
	blockSize := n.BitLen() / 8 // Размер блока для расшифрования
	// Разбиваем зашифрованные данные на блоки и расшифровываем каждый блок
	for i := 0; i < len(data); i += blockSize {
		block := data[i:min(i+blockSize, len(data))]
		// Преобразуем блок в число
		blockInt := new(big.Int).SetBytes(block)
		// Расшифруем блок
		decryptedBlock := decryptRSA(blockInt, d, n)
		// Добавляем расшифрованные данные
		decryptedData = append(decryptedData, decryptedBlock.Bytes()...)
	}
	return decryptedData
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func saveKeyToFile(filename string, key *big.Int) error {
	return ioutil.WriteFile(filename, []byte(key.String()), 0644)
}

func readKeyFromFile(filename string) (*big.Int, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	// Конвертация данных в big.Int
	key := new(big.Int)
	key.SetString(string(data), 10)
	return key, nil
}
