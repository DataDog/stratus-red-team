package utils

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/rand"
)

func CoalesceErr(args ...error) error {
	for i := range args {
		if args[i] != nil {
			return args[i]
		}
	}

	return nil
}

func RandomString(length int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func RandomHexString(length int) string {
	const letterBytes = "abcdef0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

// The Min function returns the smallest of two integers
// Note: math.Min only works for float64
func Min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

// Remove removes an element from a slice at a given index
func Remove(slice []string, index int) []string {
	return append(slice[:index], slice[index+1:]...)
}

// IndexOf returns the index of a given value in a slice, or -1 if not found
func IndexOf[T comparable](slice []T, searchValue T) int {
	for i, current := range slice {
		if current == searchValue {
			return i
		}
	}
	return -1
}

func MD5HashBase64(text string) string {
	hash := md5.Sum([]byte(text))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func SHA256Hash(input string) string {
	hash := sha256.New()
	hash.Write([]byte(input))
	return hex.EncodeToString(hash.Sum(nil))
}

func SHA256HashBase64(input []byte) string {
	hash := sha256.Sum256(input)
	return base64.StdEncoding.EncodeToString(hash[:])
}
