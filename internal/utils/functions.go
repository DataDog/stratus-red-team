package utils

import (
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
