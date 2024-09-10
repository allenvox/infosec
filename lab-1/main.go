package main

import (
	"fmt"
)

func main() {
	fmt.Println("Лабораторная работа №1")

	fmt.Println("\n1. Быстрое возведение в степень по модулю")
	fmt.Printf("%d^%d mod %d = %d\n", 5, 3, 13, modExp(5, 3, 13))
	fmt.Printf("%d^%d mod %d = %d\n", 7, 5, 19, modExp(7, 5, 19))
	fmt.Printf("%d^%d mod %d = %d\n", 9, 3, 11, modExp(9, 3, 11))

	fmt.Println("\n2. Расширенный алгоритм Евклида")
	a := int64(30)
	b := int64(12)
	gcd, x, y := extendedGCD(a, b)
	fmt.Printf("gcd(%d, %d) = %d, x = %d, y = %d\n", a, b, gcd, x, y)

	fmt.Println("\n3. Построение общего ключа по схеме Диффи-Хеллмана")
	p := int64(23)        // Простое число
	g := int64(5)         // Основание
	privateA := int64(6)  // Секретный ключ первого абонента
	privateB := int64(15) // Секретный ключ второго абонента
	sharedKeyA, sharedKeyB := diffieHellman(p, g, privateA, privateB)
	fmt.Printf("Shared key A: %d, Shared key B: %d\n", sharedKeyA, sharedKeyB)

	fmt.Println("\n4. Нахождение дискретного логарифма методом 'Шаг младенца, шаг великана'")
	g2 := int64(2)
	y2 := int64(8)
	p2 := int64(11)
	logResult := babyStepGiantStep(g2, y2, p2)
	fmt.Printf("Дискретный логарифм: log_%d(%d) mod %d = %d\n", g2, y2, p2, logResult)
}
