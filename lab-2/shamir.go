package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var pShamir = big.NewInt(7919) // Простое число

func generateRandomBigInt(limit *big.Int) *big.Int {
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		panic(err)
	}
	return n
}

func shamirEncrypt(data []byte) []byte {
	fmt.Println("Шифрование Шамира")
	// Алгоритм Шамира требует выполнения шифрования обеими сторонами
	k1 := generateRandomBigInt(pShamir) // Секрет первого участника
	k2 := generateRandomBigInt(pShamir) // Секрет второго участника

	m := new(big.Int).SetBytes(data)
	c := new(big.Int).Exp(m, k1, pShamir) // Первый этап шифрования
	c.Exp(c, k2, pShamir)                 // Второй этап шифрования

	return c.Bytes()
}

func shamirDecrypt(data []byte) []byte {
	fmt.Println("Расшифрование Шамира")
	k1 := generateRandomBigInt(pShamir)
	k2 := generateRandomBigInt(pShamir)

	c := new(big.Int).SetBytes(data)
	d := new(big.Int).Exp(c, new(big.Int).ModInverse(k2, pShamir), pShamir)
	d.Exp(d, new(big.Int).ModInverse(k1, pShamir), pShamir)

	return d.Bytes()
}
