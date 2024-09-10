package main

import (
	"crypto/rand"
	"math/big"
)

func generateRandomBigInt(limit *big.Int) *big.Int {
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		panic(err)
	}
	return n
}

var pShamir = big.NewInt(7919)

func shamirEncrypt(data []byte) []byte {
	// keys
	k1 := generateRandomBigInt(pShamir)
	k2 := generateRandomBigInt(pShamir)

	m := new(big.Int).SetBytes(data)      // message in bytes
	c := new(big.Int).Exp(m, k1, pShamir) // c = m^k1 mod p
	c.Exp(c, k2, pShamir)                 // c = c^k2 mod p

	return c.Bytes()
}

func shamirDecrypt(data []byte) []byte {
	// keys
	k1 := generateRandomBigInt(pShamir)
	k2 := generateRandomBigInt(pShamir)

	c := new(big.Int).SetBytes(data)                                        // encrypted message
	d := new(big.Int).Exp(c, new(big.Int).ModInverse(k2, pShamir), pShamir) // d = c^(k2^(-1)) mod p
	d.Exp(d, new(big.Int).ModInverse(k1, pShamir), pShamir)                 // d = d^(k1^(-1)) mod p

	return d.Bytes()
}
