package main

import (
	"crypto/rand"
	"math/big"
)

// Генерация ключей для Эль-Гамаля
func generateElGamalKeys(p, g *big.Int) (*big.Int, *big.Int, *big.Int) {
	x, _ := rand.Int(rand.Reader, p) // Закрытый ключ x
	y := new(big.Int).Exp(g, x, p)   // Открытый ключ y = g^x mod p
	return x, y, g
}

// Подписание хэша (сообщения) с использованием Эль-Гамаля
func elGamalSign(hash []byte, p, g, x *big.Int) (*big.Int, *big.Int, error) {
	k, _ := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(1))) // Случайное k
	for new(big.Int).GCD(nil, nil, k, new(big.Int).Sub(p, big.NewInt(1))).Cmp(big.NewInt(1)) != 0 {
		k, _ = rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(1))) // Генерация нового k, если k и p-1 не взаимно просты
	}

	r := new(big.Int).Exp(g, k, p) // r = g^k mod p

	kInv := new(big.Int).ModInverse(k, new(big.Int).Sub(p, big.NewInt(1))) // k^(-1) mod (p-1)
	hashInt := new(big.Int).SetBytes(hash)
	s := new(big.Int).Mul(kInv, new(big.Int).Sub(hashInt, new(big.Int).Mul(x, r))) // s = k^(-1) * (h - x*r) mod (p-1)
	s.Mod(s, new(big.Int).Sub(p, big.NewInt(1)))

	return r, s, nil
}

// Проверка подписи
func elGamalVerify(hash []byte, r, s, p, g, y *big.Int) bool {
	if r.Cmp(big.NewInt(1)) < 0 || r.Cmp(p) >= 0 || s.Cmp(big.NewInt(0)) <= 0 || s.Cmp(new(big.Int).Sub(p, big.NewInt(1))) >= 0 {
		return false
	}

	hashInt := new(big.Int).SetBytes(hash)

	// Вычисляем v1 = g^h mod p
	v1 := new(big.Int).Exp(g, hashInt, p)

	// Вычисляем v2 = y^r * r^s mod p
	v2 := new(big.Int).Mul(new(big.Int).Exp(y, r, p), new(big.Int).Exp(r, s, p))
	v2.Mod(v2, p)

	return v1.Cmp(v2) == 0
}
