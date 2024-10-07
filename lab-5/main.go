package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// Структура для бюллетеня
type Ballot struct {
	Vote string
}

// Структура для запроса слепой подписи
type BlindSignatureRequest struct {
	BlindedMessage string
}

// Структура для ответа слепой подписи
type BlindSignatureResponse struct {
	Signature string
}

// Сервер: генерирует подпись бюллетеня
func signBlindMessage(serverPrivKey *rsa.PrivateKey, blindedMessage string) string {
	blindedMessageBytes, _ := base64.StdEncoding.DecodeString(blindedMessage)
	blindedInt := new(big.Int).SetBytes(blindedMessageBytes)

	// Подписываем зашифрованное сообщение
	signatureInt := new(big.Int).Exp(blindedInt, serverPrivKey.D, serverPrivKey.N)

	// Преобразуем подпись обратно в строку
	return base64.StdEncoding.EncodeToString(signatureInt.Bytes())
}

// Клиент: заслепляет сообщение (бюллетень)
func blindMessage(message string, pubKey *rsa.PublicKey) (*big.Int, *big.Int, string, error) {
	// Хэшируем сообщение
	hash := sha256.Sum256([]byte(message))
	hashInt := new(big.Int).SetBytes(hash[:])

	// Генерируем случайное число r, взаимно простое с n
	r, err := rand.Int(rand.Reader, pubKey.N)
	if err != nil {
		return nil, nil, "", errors.New("error generating random r")
	}

	// Заслепляем сообщение: m' = m * r^e mod n
	rExpE := new(big.Int).Exp(r, big.NewInt(int64(pubKey.E)), pubKey.N)
	blindedMessage := new(big.Int).Mul(hashInt, rExpE)
	blindedMessage.Mod(blindedMessage, pubKey.N)

	return r, hashInt, base64.StdEncoding.EncodeToString(blindedMessage.Bytes()), nil
}

// Клиент: разслепляет сообщение (после получения подписи)
func unblindSignature(signature string, r *big.Int, pubKey *rsa.PublicKey) string {
	signatureBytes, _ := base64.StdEncoding.DecodeString(signature)
	sigInt := new(big.Int).SetBytes(signatureBytes)

	// Разслепляем: s' = s / r mod n
	rInv := new(big.Int).ModInverse(r, pubKey.N)
	unblindedSignature := new(big.Int).Mul(sigInt, rInv)
	unblindedSignature.Mod(unblindedSignature, pubKey.N)

	return base64.StdEncoding.EncodeToString(unblindedSignature.Bytes())
}

// Клиент: проверяет подпись
func verifySignature(message string, signature string, pubKey *rsa.PublicKey) bool {
	hash := sha256.Sum256([]byte(message))
	hashInt := new(big.Int).SetBytes(hash[:])

	signatureBytes, _ := base64.StdEncoding.DecodeString(signature)
	sigInt := new(big.Int).SetBytes(signatureBytes)

	// Проверяем подпись: s^e mod n == H(m)
	expectedHash := new(big.Int).Exp(sigInt, big.NewInt(int64(pubKey.E)), pubKey.N)

	return expectedHash.Cmp(hashInt) == 0
}

// Валидация бюллетеня
func validateBallot(ballot Ballot) error {
	validVotes := []string{"Да", "Нет", "Воздержался"}
	for _, validVote := range validVotes {
		if ballot.Vote == validVote {
			return nil
		}
	}
	return errors.New("invalid vote: " + ballot.Vote)
}

// Серверная часть: подписывание
func serverSide(blindSignatureRequest BlindSignatureRequest, serverPrivKey *rsa.PrivateKey) BlindSignatureResponse {
	signature := signBlindMessage(serverPrivKey, blindSignatureRequest.BlindedMessage)
	return BlindSignatureResponse{Signature: signature}
}

// Клиентская часть: процесс голосования
func clientSide(ballot Ballot, serverPubKey *rsa.PublicKey, serverPrivKey *rsa.PrivateKey) {
	fmt.Println("Клиент: Начало голосования")

	// Проверка на допустимые значения
	err := validateBallot(ballot)
	if err != nil {
		fmt.Println("Ошибка:", err)
		return
	}
	fmt.Printf("Выбранный голос: %s\n", ballot.Vote)

	// Заслепление бюллетеня
	fmt.Println("Клиент: Заслепление бюллетеня")
	r, _, blindedMessage, err := blindMessage(ballot.Vote, serverPubKey)
	if err != nil {
		fmt.Println("Ошибка при заслеплении:", err)
		return
	}
	fmt.Println("Заслеплённый бюллетень отправляется на сервер:", blindedMessage)

	// Отправка "слепого" сообщения серверу
	request := BlindSignatureRequest{BlindedMessage: blindedMessage}
	response := serverSide(request, serverPrivKey)

	// Клиент получает слепую подпись и разслепляет её
	fmt.Println("Клиент: Получена слепая подпись, разслепление")
	unblindedSignature := unblindSignature(response.Signature, r, serverPubKey)
	fmt.Println("Разслепленная подпись:", unblindedSignature)

	// Проверка подписи
	fmt.Println("Клиент: Проверка подписи")
	if verifySignature(ballot.Vote, unblindedSignature, serverPubKey) {
		fmt.Println("Подпись успешно проверена!")
	} else {
		fmt.Println("Ошибка проверки подписи!")
	}
}

func main() {
	// Генерация ключей RSA для сервера
	serverPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	serverPubKey := &serverPrivKey.PublicKey

	// Клиент готовит бюллетень
	ballot := Ballot{Vote: "Да"} // Измените здесь на "Нет" или "Воздержался" для проверки

	// Запуск процесса голосования
	clientSide(ballot, serverPubKey, serverPrivKey)
}
