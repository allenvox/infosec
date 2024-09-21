package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Использование: go run . <encrypt|decrypt> <algorithm> <filename>")
		return
	}
	action := os.Args[1]
	algorithm := os.Args[2]
	filename := os.Args[3]
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Ошибка чтения файла:", err)
		return
	}

	var result []byte
	switch algorithm {
	case "shamir":
		if action == "encrypt" {
			result = shamirEncrypt(data)
		} else {
			result = shamirDecrypt(data)
		}
	case "elgamal":
		if action == "encrypt" {
			result = elGamalEncrypt(data)
		} else {
			result = elGamalDecrypt(data)
		}
	case "vernam":
		if action == "encrypt" {
			result = vernamEncrypt(data)
		} else {
			result = vernamDecrypt(data)
		}
	case "rsa":
		if action == "encrypt" {
			bitLen := 512 // key size
			e, d, n, _ := generateRSAKeys(bitLen)
			err := saveKeyToFile("public_key.txt", e)
			if err != nil {
				fmt.Printf("Ошибка сохранения открытого ключа: %v\n", err)
				return
			}
			err = saveKeyToFile("private_key.txt", d)
			if err != nil {
				fmt.Printf("Ошибка сохранения закрытого ключа: %v\n", err)
				return
			}
			err = saveKeyToFile("n.txt", n) // n также нужен для шифрования/расшифровывания
			if err != nil {
				fmt.Printf("Ошибка сохранения модуля n: %v\n", err)
				return
			}
			fmt.Println("Ключи успешно сохранены в файлы.")
			result = rsaEncrypt(data, e, n)
		} else {
			nKey, err := readKeyFromFile("n.txt")
			if err != nil {
				fmt.Printf("Ошибка чтения модуля n: %v\n", err)
				return
			}
			privateKey, err := readKeyFromFile("private_key.txt")
			if err != nil {
				fmt.Printf("Ошибка чтения закрытого ключа: %v\n", err)
				return
			}
			result = rsaDecrypt(data, privateKey, nKey)
		}
	default:
		fmt.Println("Неизвестный алгоритм. Доступные алгоритмы: shamir, elgamal, vernam, rsa")
		return
	}

	outputFilename := filename + ".out"
	err = ioutil.WriteFile(outputFilename, result, 0644)
	if err != nil {
		fmt.Println("Ошибка записи в файл:", err)
		return
	}
	fmt.Printf("Операция %s с использованием %s выполнена. Результат записан в %s\n", action, algorithm, outputFilename)
}
