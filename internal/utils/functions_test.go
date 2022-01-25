package utils

import (
	"errors"
	"github.com/stretchr/testify/assert"

	"testing"
)

func TestRandomString(t *testing.T) {
	assert.Len(t, RandomString(16), 16)
}

func TestCoalesceErr(t *testing.T) {
	assert.Equal(t, nil, CoalesceErr(nil, nil, nil))
	assert.Equal(t, "foo", CoalesceErr(errors.New("foo"), errors.New("bar"), errors.New("barz")).Error())
	assert.Equal(t, "bar", CoalesceErr(nil, errors.New("bar"), errors.New("barz")).Error())
}
