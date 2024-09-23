package main

import (
	"math/big"
)

var pElGamal = big.NewInt(7919)
var gElGamal = big.NewInt(2)
var x = big.NewInt(3137)
var k = big.NewInt(773)

func elGamalEncrypt(data []byte) []byte {
	y := new(big.Int).Exp(gElGamal, x, pElGamal)               // public key (g^x mod p)
	a := new(big.Int).Exp(gElGamal, k, pElGamal)               // g^k mod p
	m := new(big.Int).SetBytes(data)                           // message
	b := new(big.Int).Mul(m, new(big.Int).Exp(y, k, pElGamal)) // (m * y^k) mod p
	b.Mod(b, pElGamal)

	return append(a.Bytes(), b.Bytes()...)
}

func elGamalDecrypt(data []byte) []byte {
	a := new(big.Int).SetBytes(data[:len(data)/2])
	b := new(big.Int).SetBytes(data[len(data)/2:])

	s := new(big.Int).Exp(a, x, pElGamal)        // s = a^x mod p
	sInv := new(big.Int).ModInverse(s, pElGamal) // inversion of s
	m := new(big.Int).Mul(b, sInv)               // message
	m.Mod(m, pElGamal)

	return m.Bytes()
}
