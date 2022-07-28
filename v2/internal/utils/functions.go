package utils

import (
	"math/rand"
	"time"
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
	rand.Seed(time.Now().UnixNano())
	const letterBytes = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func RandomHexString(length int) string {
	rand.Seed(time.Now().UnixNano())
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
