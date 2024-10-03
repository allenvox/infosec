package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	mathRand "math/rand"
	"time"
)

type Card struct {
	Suit  string
	Value string
}

type Player struct {
	ID      int
	PrivKey *rsa.PrivateKey
	PubKey  *rsa.PublicKey
}

func createDeck() []Card {
	suits := []string{"Hearts", "Diamonds", "Clubs", "Spades"}
	values := []string{"2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A"}
	deck := []Card{}
	for _, suit := range suits {
		for _, value := range values {
			deck = append(deck, Card{Suit: suit, Value: value})
		}
	}
	return deck
}

func shuffleDeck(deck []Card) []Card {
	r := mathRand.New(mathRand.NewSource(time.Now().Unix()))
	for i := range deck {
		j := r.Intn(len(deck))
		deck[i], deck[j] = deck[j], deck[i]
	}
	return deck
}

// Generate RSA keys for all players
func generateKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048) // Используем cryptoRand для генерации ключей
	if err != nil {
		fmt.Println("Ошибка генерации ключей RSA:", err)
		return nil, nil
	}
	return privKey, &privKey.PublicKey
}

// Create players with their keys
func createPlayers(numPlayers int) []Player {
	players := make([]Player, numPlayers)
	for i := 0; i < numPlayers; i++ {
		privKey, pubKey := generateKeys()
		players[i] = Player{ID: i + 1, PrivKey: privKey, PubKey: pubKey}
	}
	return players
}

func encryptCard(card string, pubKey *rsa.PublicKey) []byte {
	label := []byte("") // empty label, can be used for additional security
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pubKey, []byte(card), label) // Используем cryptoRand для шифрования
	if err != nil {
		fmt.Println("Ошибка шифрования:", err)
		return nil
	}
	return ciphertext
}

func decryptCard(ciphertext []byte, privKey *rsa.PrivateKey) string {
	label := []byte("")
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, ciphertext, label)
	if err != nil {
		fmt.Println("Ошибка расшифровки:", err)
		return ""
	}
	return string(plaintext)
}

func dealCards(players []Player, deck []Card) [][]Card {
	hands := make([][]Card, len(players))
	for i := range players {
		hands[i] = []Card{deck[i], deck[i+len(players)]}
	}
	return hands
}

// Player decrypts his cards with private key
func revealCard(card []byte, player Player) string {
	return decryptCard(card, player.PrivKey)
}

func main() {
	numPlayers := 4
	players := createPlayers(numPlayers)

	deck := createDeck()
	deck = shuffleDeck(deck)

	// Encrypt cards for all players
	encryptedDeck := make([][]byte, len(deck))
	for i, card := range deck {
		cardString := fmt.Sprintf("%s of %s", card.Value, card.Suit)
		// Каждый игрок шифрует колоду своим публичным ключом
		for _, player := range players {
			encryptedDeck[i] = encryptCard(cardString, player.PubKey)
		}
	}

	hands := dealCards(players, deck)

	// Players decrypt their cards
	for i, player := range players {
		fmt.Printf("Игрок %d расшифровывает карты:\n", player.ID)
		for _, card := range hands[i] {
			cardString := fmt.Sprintf("%s of %s", card.Value, card.Suit)
			encryptedCard := encryptCard(cardString, player.PubKey)
			decryptedCard := revealCard(encryptedCard, player)
			fmt.Printf("Расшифрованная карта: %s\n", decryptedCard)
		}
	}

	// Get cards from board
	board := deck[numPlayers*2 : numPlayers*2+5]
	fmt.Println("Карты на столе:")
	for _, card := range board {
		fmt.Printf("%s of %s\n", card.Value, card.Suit)
	}
}
