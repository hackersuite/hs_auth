package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_SampleFunc(t *testing.T) {
	assert.Equal(t, SampleFunc(9, 10), 19)
}
