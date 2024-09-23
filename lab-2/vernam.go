package main

import (
	"crypto/rand"
	"io/ioutil"
)

// Генерация ключа той же длины, что и данные
func generateKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Сохранение ключа в файл
func saveVernamKeyToFile(filename string, key []byte) error {
	return ioutil.WriteFile(filename, key, 0644)
}

// Чтение ключа из файла
func readVernamKeyFromFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// Шифрование и расшифрование шифром Вернама
func vernamEncryptDecrypt(data []byte, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i] // XOR между данными и ключом
	}
	return result
}

// Шифрование данных с использованием Вернама
func vernamEncrypt(data []byte) ([]byte, error) {
	// Генерируем ключ той же длины, что и данные
	key, err := generateKey(len(data))
	if err != nil {
		return nil, err
	}

	// Сохраняем ключ в файл
	err = saveVernamKeyToFile("vernam_key.txt", key)
	if err != nil {
		return nil, err
	}

	// Шифруем данные с помощью XOR
	encryptedData := vernamEncryptDecrypt(data, key)
	return encryptedData, nil
}

// Расшифрование данных с использованием Вернама
func vernamDecrypt(data []byte) ([]byte, error) {
	// Считываем ключ из файла
	key, err := readVernamKeyFromFile("vernam_key.txt")
	if err != nil {
		return nil, err
	}

	// Расшифровываем данные с помощью XOR
	decryptedData := vernamEncryptDecrypt(data, key)
	return decryptedData, nil
}
