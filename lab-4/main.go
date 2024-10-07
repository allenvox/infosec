package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	mathRand "math/rand"
	"time"
)

type Card struct {
	Value string
	Suit  string
}

func createDeck() []Card { // shuffled
	values := []string{"2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A"}
	suits := []string{"Hearts", "Diamonds", "Clubs", "Spades"}
	var deck []Card
	for _, suit := range suits {
		for _, value := range values {
			deck = append(deck, Card{Value: value, Suit: suit})
		}
	}
	mathRand.Seed(time.Now().UnixNano())
	mathRand.Shuffle(len(deck), func(i, j int) { deck[i], deck[j] = deck[j], deck[i] })
	return deck
}

func encryptCard(card string, pubKey *rsa.PublicKey) (string, string) {
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pubKey, []byte(card), nil)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return "", ""
	}
	hashValue := sha256.Sum256([]byte(card))
	return base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(hashValue[:])
}

func decryptCard(ciphertext string, privKey *rsa.PrivateKey) (string, error) {
	hash := sha256.New()
	cipherData, _ := base64.StdEncoding.DecodeString(ciphertext)
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, cipherData, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func verifyCard(card string, expectedHash string) bool {
	hashValue := sha256.Sum256([]byte(card))
	calculatedHash := base64.StdEncoding.EncodeToString(hashValue[:])
	return calculatedHash == expectedHash
}

type Player struct {
	Name           string
	PrivateKey     *rsa.PrivateKey
	PublicKey      *rsa.PublicKey
	Hand           []Card
	EncryptedCards []string
	Hashes         []string
}

func createPlayers(names []string) []Player {
	var players []Player
	for _, name := range names {
		privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		players = append(players, Player{
			Name:       name,
			PrivateKey: privKey,
			PublicKey:  &privKey.PublicKey,
		})
	}
	return players
}

func dealCards(players []Player, deck []Card, numCardsPerPlayer int) {
	for i := 0; i < numCardsPerPlayer; i++ {
		for j := range players {
			players[j].Hand = append(players[j].Hand, deck[0])
			deck = deck[1:]
		}
	}
}

func gameExample() {
	deck := createDeck()
	numPlayers := 3
	playerNames := []string{"Amanda", "Boris", "Sebastian"}
	players := createPlayers(playerNames)

	// 1. Раздаем карты игрокам
	dealCards(players, deck, 2)

	// 2. Игроки шифруют свои карты с использованием своих публичных ключей
	for i, player := range players {
		fmt.Printf("\n%s encrypts their cards:\n", player.Name)
		for _, card := range player.Hand {
			cardData := card.Value + " of " + card.Suit
			encryptedCard, cardHash := encryptCard(cardData, player.PublicKey)
			player.EncryptedCards = append(player.EncryptedCards, encryptedCard)
			player.Hashes = append(player.Hashes, cardHash)
			fmt.Printf("Encrypted card: %s\n", encryptedCard)
		}
		players[i] = player
	}

	// 3. Вскрываем карты, каждый игрок расшифровывает свои карты
	for _, player := range players {
		fmt.Printf("\n%s reveals their cards and everyone verifies:\n", player.Name)
		for i, encryptedCard := range player.EncryptedCards {
			// Только сам игрок расшифровывает свои карты
			decryptedCard, err := decryptCard(encryptedCard, player.PrivateKey)
			if err != nil {
				fmt.Println("Card decryption error:", err)
				continue
			}
			fmt.Printf("%s decrypts: %s\n", player.Name, decryptedCard)

			// Остальные игроки проверяют целостность карты по хэшу
			for _, otherPlayer := range players {
				if otherPlayer.Name != player.Name {
					if verifyCard(decryptedCard, player.Hashes[i]) {
						fmt.Printf("%s verified card of %s: Card %d verified!\n", otherPlayer.Name, player.Name, i+1)
					} else {
						fmt.Printf("%s verification of card %d failed!\n", otherPlayer.Name, i+1)
					}
				}
			}
		}
	}

	// 4. Карты на борде
	board := deck[numPlayers*2 : numPlayers*2+5]
	fmt.Println("\nCards on board:")
	for _, card := range board {
		fmt.Printf("%s of %s\n", card.Value, card.Suit)
	}
}

func attackExample() {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Keys generation error:", err)
		return
	}
	pubKey := &privKey.PublicKey

	card := "Ace of Spades" // example

	// Card encryption
	encryptedCard, expectedHash := encryptCard(card, pubKey)
	fmt.Println("Encrypted card:", encryptedCard)
	fmt.Println("Expected hash:", expectedHash)

	decryptedCard, err := decryptCard(encryptedCard, privKey)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}
	fmt.Println("Decrypted card:", decryptedCard)

	// Card verification
	if verifyCard(decryptedCard, expectedHash) {
		fmt.Println("Card verified!")
	} else {
		fmt.Println("Bad card! Verification fail")
	}

	// Invalid key attack
	invalidKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err = decryptCard(encryptedCard, invalidKey)
	if err != nil {
		fmt.Println("Bad card! Verification fail:", err)
	} else {
		fmt.Println("Successfull decryption with invalid key (security leak)")
	}
}

func main() {
	fmt.Println("Game example:")
	gameExample()
	fmt.Println("\nRSA attack example:")
	attackExample()
}
