package util

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitArgs(t *testing.T) {
	for _, testCase := range []struct {
		input       string
		expectLeft  []string
		expectRight []string
	}{
		{
			input:       "./rancher-machine rm -y myhost -- --driver-arg thing -m",
			expectLeft:  strings.Split("./rancher-machine rm -y myhost", " "),
			expectRight: strings.Split("--driver-arg thing -m", " "),
		},
		{
			input:       "./rancher-machine rm -y myhost",
			expectLeft:  strings.Split("./rancher-machine rm -y myhost", " "),
			expectRight: []string{},
		},
	} {
		args := strings.Split(testCase.input, " ")
		left, right := SplitArgs(args)
		assert.Equal(t, testCase.expectLeft, left)
		assert.Equal(t, testCase.expectRight, right)
	}
}
