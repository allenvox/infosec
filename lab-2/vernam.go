package main

import (
	"math/rand"
)

func vernamEncrypt(data []byte) []byte {
	key := generateVernamKey(len(data))
	return xorBytes(data, key)
}

func vernamDecrypt(data []byte) []byte {
	key := generateVernamKey(len(data))
	return xorBytes(data, key)
}

func generateVernamKey(length int) []byte {
	key := make([]byte, length)
	for i := range key {
		key[i] = byte(rand.Intn(256))
	}
	return key
}

func xorBytes(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}
