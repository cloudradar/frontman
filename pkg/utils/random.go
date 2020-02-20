package utils

import "math/rand"

var letters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

// randomizedStr returns string of len strLen
// probability of all the letters will not be exactly the same
func RandomizedStr(strLen int) string {
	b := make([]byte, strLen)
	for i := range b {
		b[i] = letters[rand.Int63()%int64(len(letters))]
	}
	return string(b)
}
