package main

import (
	"math"
)

// Быстрое возведение в степень по модулю
func modExp(base, exp, mod int64) int64 {
	result := int64(1)
	base = base % mod
	for exp > 0 {
		if exp%2 == 1 {
			result = (result * base) % mod
		}
		exp = exp >> 1
		base = (base * base) % mod
	}
	return result
}

// Расширенный алгоритм Евклида: возвращает gcd, x, y
func extendedGCD(a, b int64) (int64, int64, int64) {
	if b == 0 {
		return a, 1, 0
	}
	gcd, x1, y1 := extendedGCD(b, a%b)
	x := y1
	y := x1 - (a/b)*y1
	return gcd, x, y
}

// Построение общего ключа по схеме Диффи-Хеллмана
func diffieHellman(p, g, privateA, privateB int64) (int64, int64) {
	publicA := modExp(g, privateA, p) // g^a mod p
	publicB := modExp(g, privateB, p) // g^b mod p

	// Обмен публичными ключами
	sharedKeyA := modExp(publicB, privateA, p) // (g^b)^a mod p
	sharedKeyB := modExp(publicA, privateB, p) // (g^a)^b mod p

	return sharedKeyA, sharedKeyB // sharedKeyA должно быть равно sharedKeyB
}

// Алгоритм "Шаг младенца, шаг великана"
func babyStepGiantStep(g, y, p int64) int64 {
	m := int64(math.Ceil(math.Sqrt(float64(p))))
	valueMap := make(map[int64]int64)

	// Шаг младенца: вычисляем g^j mod p для j от 0 до m-1
	babyStep := int64(1)
	for j := int64(0); j < m; j++ {
		valueMap[babyStep] = j
		babyStep = (babyStep * g) % p
	}

	// Шаг великана: ищем соответствие
	factor := modExp(g, p-m-1, p) // g^(m*(p-2)) mod p
	giantStep := y
	for i := int64(0); i < m; i++ {
		if j, exists := valueMap[giantStep]; exists {
			return i*m + j
		}
		giantStep = (giantStep * factor) % p
	}

	// Если логарифм не найден
	return -1
}
