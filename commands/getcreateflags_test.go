package commands

import (
	"fmt"
	"testing"

	"github.com/rancher/machine/libmachine/mcnflag"
	"github.com/stretchr/testify/assert"
)

func Test_fieldFromFlag(t *testing.T) {
	tests := []struct {
		name    string
		flag    mcnflag.Flag
		want    field
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "string flag",
			flag: &mcnflag.StringFlag{
				Name:   "test-string",
				Usage:  "test usage",
				EnvVar: "TEST_STRING", // ignored
				Value:  "default",
			},
			want: field{
				Name:        "test-string",
				Type:        "string",
				Description: "test usage",
				Default:     "default",
			},
			wantErr: assert.NoError,
		},
		{
			name: "bool flag",
			flag: &mcnflag.BoolFlag{
				Name:  "test-bool",
				Usage: "test usage",
			},
			want: field{
				Name:        "test-bool",
				Type:        "boolean",
				Description: "test usage",
				Default:     false,
			},
			wantErr: assert.NoError,
		},
		{
			name: "int flag",
			flag: &mcnflag.IntFlag{
				Name:  "test-int",
				Usage: "test usage",
				Value: 42,
			},
			want: field{
				Name:        "test-int",
				Type:        "integer",
				Description: "test usage",
				Default:     42,
			},
			wantErr: assert.NoError,
		},
		{
			name: "string slice flag",
			flag: &mcnflag.StringSliceFlag{
				Name:  "test-slice",
				Usage: "test usage",
				Value: []string{"uno", "dos", "tres"},
			},
			want: field{
				Name:        "test-slice",
				Type:        "stringSlice",
				Description: "test usage",
				Default:     []string{"uno", "dos", "tres"},
			},
			wantErr: assert.NoError,
		},
		{
			name:    "unknown flag",
			flag:    &invalidFlag{},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fieldFromFlag(tt.flag)
			if !tt.wantErr(t, err, fmt.Sprintf("fieldFromFlag(%v)", tt.flag)) {
				return
			}
			assert.Equalf(t, tt.want, got, "fieldFromFlag(%v)", tt.flag)
		})
	}
}

type invalidFlag struct{}

func (invalidFlag) String() string {
	return "invalid"
}

func (invalidFlag) Default() any {
	return nil
}
