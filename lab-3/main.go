package main

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
)

func computeFileHash(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	return hash[:], nil
}

func writeSignatureToFile(r, s *big.Int, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file %v", err)
	}
	defer file.Close()
	_, err = fmt.Fprintf(file, "%s\n%s\n", r.String(), s.String())
	if err != nil {
		return fmt.Errorf("error writing signature")
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Использование: go run . <elgamal|rsa|gost>")
		return
	}
	filename := "../example.txt"
	hash, err := computeFileHash(filename)
	if err != nil {
		fmt.Printf("Ошибка при вычислении хэша файла: %v\n", err)
		return
	}
	fmt.Printf("Хэш файла: %x\n", hash)

	algorithm := os.Args[1]
	switch algorithm {

	case "elgamal":

		// Генерация ключей
		p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
		g := big.NewInt(2)

		x, y, _ := generateElGamalKeys(p, g)
		fmt.Printf("Закрытый ключ x: %s\n", x.String())
		fmt.Printf("Открытый ключ y: %s\n", y.String())

		// Подписание хэша файла
		r, s, err := elGamalSign(hash, p, g, x)
		if err != nil {
			fmt.Printf("Ошибка при подписании: %v\n", err)
			return
		}
		fmt.Printf("Подпись: r = %s, s = %s\n", r.String(), s.String())
		writeSignatureToFile(r, s, "sign.elgamal")

		// Проверка подписи
		valid := elGamalVerify(hash, r, s, p, g, y)
		if valid {
			fmt.Println("Подпись корректна!")
		} else {
			fmt.Println("Подпись некорректна!")
		}

	case "rsa":

		// Генерация ключей RSA
		privateKey, err := generateRSAKeys(2048)
		if err != nil {
			fmt.Printf("Ошибка генерации ключей: %v\n", err)
			return
		}

		// Сохранение ключей в файлы
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

		// Подписание файла
		signature, err := rsaSign(hash, privateKey)
		if err != nil {
			fmt.Printf("Ошибка при подписании файла: %v\n", err)
			return
		}
		fmt.Printf("Подпись файла: %x\n", signature)
		ioutil.WriteFile("sign.rsa", signature, 0644)

		// Проверка подписи
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

	case "gost":

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
		writeSignatureToFile(r, s, "sign.gost")

		// Проверка подписи
		valid := gostVerify(hash, r, s, &privateKey.PublicKey)
		if valid {
			fmt.Println("Подпись корректна!")
		} else {
			fmt.Println("Подпись некорректна!")
		}

	default:
		fmt.Println("Неизвестный алгоритм. Доступные алгоритмы: elgamal, rsa, gost")
		return
	}
}
