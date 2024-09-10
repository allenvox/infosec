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

	// Чтение содержимого файла
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
			result = rsaEncrypt(data)
		} else {
			result = rsaDecrypt(data)
		}
	default:
		fmt.Println("Неизвестный алгоритм. Доступные алгоритмы: shamir, elgamal, vernam, rsa")
		return
	}

	// Запись результата в новый файл
	outputFilename := filename + ".out"
	err = ioutil.WriteFile(outputFilename, result, 0644)
	if err != nil {
		fmt.Println("Ошибка записи в файл:", err)
		return
	}

	fmt.Printf("Операция %s с использованием %s выполнена. Результат записан в %s\n", action, algorithm, outputFilename)
}
