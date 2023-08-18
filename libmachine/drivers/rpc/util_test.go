package rpcdriver

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rancher/machine/libmachine/mcnflag"
	"github.com/stretchr/testify/assert"
)

func TestGetDriverOpts(t *testing.T) {
	flags := []mcnflag.Flag{
		mcnflag.StringFlag{
			Name: "string-value",
		},
		mcnflag.StringFlag{
			Name:  "default-string-value",
			Value: "default",
		},
		mcnflag.IntFlag{
			Name: "int-value",
		},
		mcnflag.IntFlag{
			Name:  "default-int-value",
			Value: 42,
		},
		mcnflag.StringSliceFlag{
			Name: "string-slice-value",
		},
		mcnflag.StringSliceFlag{
			Name:  "default-string-slice-value",
			Value: []string{"test", "string"},
		},
		mcnflag.BoolFlag{
			Name: "bool-value",
		},
	}
	args := strings.Split("some random args --string-value value --int-value=2 --string-slice-value one,two --bool-value", " ")
	expected := map[string]any{
		"string-value":               "value",
		"default-string-value":       "default",
		"int-value":                  2,
		"default-int-value":          42,
		"string-slice-value":         []string{"one", "two"},
		"default-string-slice-value": []string{"test", "string"},
		"bool-value":                 true,
	}

	result := GetDriverOpts(flags, args)
	assert.True(t, reflect.DeepEqual(expected, result.Values))
}
