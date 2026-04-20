package utils

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRandomString(t *testing.T) {
	assert.Len(t, RandomString(16), 16)
}

func TestCoalesceErr(t *testing.T) {
	assert.Equal(t, nil, CoalesceErr(nil, nil, nil))
	assert.Equal(t, "foo", CoalesceErr(errors.New("foo"), errors.New("bar"), errors.New("barz")).Error())
	assert.Equal(t, "bar", CoalesceErr(nil, errors.New("bar"), errors.New("barz")).Error())
}

func TestChunk(t *testing.T) {
	tests := []struct {
		name      string
		items     []int
		chunkSize int
		expected  [][]int
	}{
		{
			name:      "exact multiple",
			items:     []int{1, 2, 3, 4},
			chunkSize: 2,
			expected:  [][]int{{1, 2}, {3, 4}},
		},
		{
			name:      "with remainder",
			items:     []int{1, 2, 3, 4, 5},
			chunkSize: 2,
			expected:  [][]int{{1, 2}, {3, 4}, {5}},
		},
		{
			name:      "chunk larger than input",
			items:     []int{1, 2, 3},
			chunkSize: 10,
			expected:  [][]int{{1, 2, 3}},
		},
		{
			name:      "empty input",
			items:     []int{},
			chunkSize: 3,
			expected:  nil,
		},
		{
			name:      "non-positive chunk size",
			items:     []int{1, 2, 3},
			chunkSize: 0,
			expected:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, Chunk(tt.items, tt.chunkSize))
		})
	}
}
