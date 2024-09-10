package main

import (
	"fmt"
	"log"
)

func main() {
	fmt.Println("Работа с файлами (чтение и запись)")
	fileData := []byte("Это пример работы с файлами на языке Go.")
	err := writeFile("example.txt", fileData)
	if err != nil {
		log.Fatalf("Ошибка при записи в файл: %v", err)
	}

	readData, err := readFile("example.txt")
	if err != nil {
		log.Fatalf("Ошибка при чтении файла: %v", err)
	}
	fmt.Printf("Данные, прочитанные из файла: %s\n", string(readData))
}
