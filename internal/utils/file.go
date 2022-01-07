package utils

import "os"

func FileExists(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	} else if err != nil {
		// In case of error, we assume the file doesn't exist to make the logic simpler
		return false
	}
	return true
}
