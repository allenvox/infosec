package main

import (
	"fmt"
	"math/big"
)

var pElGamal = big.NewInt(7919)
var gElGamal = big.NewInt(2)

func elGamalEncrypt(data []byte) []byte {
	fmt.Println("Шифрование Эль-Гамаля")
	x := generateRandomBigInt(pElGamal)          // Секретный ключ
	y := new(big.Int).Exp(gElGamal, x, pElGamal) // Открытый ключ

	k := generateRandomBigInt(pElGamal) // Секретное случайное значение
	a := new(big.Int).Exp(gElGamal, k, pElGamal)
	m := new(big.Int).SetBytes(data)
	b := new(big.Int).Mul(m, new(big.Int).Exp(y, k, pElGamal))
	b.Mod(b, pElGamal)

	return append(a.Bytes(), b.Bytes()...)
}

func elGamalDecrypt(data []byte) []byte {
	fmt.Println("Расшифрование Эль-Гамаля")
	x := generateRandomBigInt(pElGamal) // Секретный ключ

	a := new(big.Int).SetBytes(data[:len(data)/2])
	b := new(big.Int).SetBytes(data[len(data)/2:])

	s := new(big.Int).Exp(a, x, pElGamal)
	sInv := new(big.Int).ModInverse(s, pElGamal)
	m := new(big.Int).Mul(b, sInv)
	m.Mod(m, pElGamal)

	return m.Bytes()
}
