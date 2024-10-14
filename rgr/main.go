package main

import (
	"fmt"
	"math/rand"
	"time"
)

// Структура для представления графа
type Graph struct {
	Vertices int
	Edges    [][2]int
	Colors   []int // Правильная раскраска графа
}

// Генерация случайного графа
func generateRandomGraph(n, m int) Graph {
	rand.Seed(time.Now().UnixNano())
	// Генерация рёбер
	edges := make(map[[2]int]bool)
	for len(edges) < m {
		v1 := rand.Intn(n) + 1
		v2 := rand.Intn(n) + 1
		if v1 != v2 {
			edge := [2]int{v1, v2}
			if v1 > v2 {
				edge = [2]int{v2, v1}
			}
			edges[edge] = true
		}
	}
	// Преобразуем карту в список рёбер
	edgeList := make([][2]int, 0, len(edges))
	for edge := range edges {
		edgeList = append(edgeList, edge)
	}
	return Graph{Vertices: n, Edges: edgeList}
}

// Жадная раскраска графа
func greedyColoring(graph Graph, numColors int) []int {
	colors := make([]int, graph.Vertices)
	for v := 0; v < graph.Vertices; v++ {
		usedColors := make([]bool, numColors+1) // Использованные цвета для данной вершины
		// Проверяем все рёбра для текущей вершины и помечаем занятые цвета
		for _, edge := range graph.Edges {
			if edge[0]-1 == v {
				usedColors[colors[edge[1]-1]] = true // Цвет соседней вершины занят
			} else if edge[1]-1 == v {
				usedColors[colors[edge[0]-1]] = true // Цвет соседней вершины занят
			}
		}
		// Присваиваем первый доступный цвет
		assigned := false
		for c := 1; c <= numColors; c++ { // Цвета начинаются с 1
			if !usedColors[c] {
				colors[v] = c
				assigned = true
				break
			}
		}
		// Если не удалось присвоить цвет, то это ошибка — граф нельзя раскрасить с заданным числом цветов
		if !assigned {
			fmt.Printf("Ошибка: невозможно раскрасить вершину %d с %d цветами\n", v+1, numColors)
			return nil
		}
	}
	return colors
}

// Случайная раскраска графа (может быть некорректной)
func randomColoring(graph Graph, numColors int) []int {
	colors := make([]int, graph.Vertices)
	for v := 0; v < graph.Vertices; v++ {
		colors[v] = rand.Intn(numColors) + 1 // Случайное присвоение цвета вершинам
	}
	return colors
}

// Применение случайной перестановки к цветам
func randomColorPermutation(colors []int, numColors int) []int {
	rand.Seed(time.Now().UnixNano())
	permutation := rand.Perm(numColors) // Генерация случайной перестановки

	permutedColors := make([]int, len(colors))
	for i, color := range colors {
		// Проверка на случай, если цвет выходит за пределы диапазона
		if color < 1 || color > numColors {
			fmt.Printf("Ошибка: цвет %d выходит за пределы диапазона от 1 до %d\n", color, numColors)
			color = rand.Intn(numColors) + 1 // Присваиваем случайный допустимый цвет
		}
		permutedColors[i] = permutation[color-1] + 1 // Применяем перестановку к цветам
	}
	return permutedColors
}

// Функция для проведения одного раунда протокола
func proofRound(graph Graph, permutedColors []int, edge [2]int) bool {
	// Верификатор выбирает одно ребро и проверяет его цвета
	v1 := edge[0] - 1
	v2 := edge[1] - 1
	colorV1 := permutedColors[v1]
	colorV2 := permutedColors[v2]
	fmt.Printf("Проверка ребра (%d, %d): Цвета вершин %d и %d\n", edge[0], edge[1], colorV1, colorV2)
	// Если цвета двух вершин на ребре разные, это корректно
	return colorV1 != colorV2
}

func zeroKnowledgeProof(graph Graph, numRounds int, numColors int) {
	fmt.Println("\nНачало протокола доказательства с нулевым знанием:")
	for round := 1; round <= numRounds; round++ {
		fmt.Printf("%d: ", round)

		// Шаг 1: Доказывающий применяет случайную перестановку цветов
		permutedColors := randomColorPermutation(graph.Colors, numColors)

		// Шаг 2: Верификатор выбирает случайное ребро для проверки
		randomEdge := graph.Edges[rand.Intn(len(graph.Edges))]

		// Шаг 3: Доказывающий показывает цвета двух вершин выбранного ребра
		if proofRound(graph, permutedColors, randomEdge) {
			fmt.Println("Верификация прошла успешно (разные цвета вершин).")
		} else {
			fmt.Println("Ошибка: одинаковые цвета у вершин ребра!")
			return
		}
	}

	fmt.Println("\nПротокол завершён: Верификатор убеждён, что раскраска правильная.")
}

func main() {
	// Количество вершин, рёбер и цветов
	n := 100        // Количество вершин
	m := 1000       // Количество рёбер
	numColors := 40 // Количество цветов
	numRounds := 50 // Количество раундов

	// Генерация случайного графа
	graph := generateRandomGraph(n, m)

	// Правильная раскраска графа
	graph.Colors = greedyColoring(graph, numColors)

	//fmt.Println("Генерация графа и правильной раскраски:")
	//fmt.Println("Рёбра графа:", graph.Edges)
	//fmt.Println("Цвета вершин:", graph.Colors)

	// Запуск протокола доказательства с нулевым знанием с правильной раскраской
	fmt.Println("Проверка с правильной раскраской:")
	zeroKnowledgeProof(graph, numRounds, numColors)

	// Случайная (возможно некорректная) раскраска
	graph.Colors = randomColoring(graph, numColors)
	fmt.Println("\nПроверка с случайной (возможно некорректной) раскраской:")
	zeroKnowledgeProof(graph, numRounds, numColors)
}
