package utils

import "crypto/sha256"

func CoalesceErr(args ...error) error {
	for i := range args {
		if args[i] != nil {
			return args[i]
		}
	}

	return nil
}

func SHA256(buf []byte) []byte {
	hash := sha256.Sum256(buf)
	return hash[:]
}
