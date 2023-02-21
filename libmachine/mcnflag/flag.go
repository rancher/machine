package mcnflag

import "fmt"

type Flag interface {
	fmt.Stringer
	Default() interface{}
	IsOptional() bool
}

type StringFlag struct {
	Name     string
	Usage    string
	EnvVar   string
	Value    string
	Optional bool
}

// TODO: Could this be done more succinctly using embedding?
func (f StringFlag) String() string {
	return f.Name
}

func (f StringFlag) Default() interface{} {
	return f.Value
}

func (f StringFlag) IsOptional() bool {
	return f.Optional
}

type StringSliceFlag struct {
	Name     string
	Usage    string
	EnvVar   string
	Value    []string
	Optional bool
}

// TODO: Could this be done more succinctly using embedding?
func (f StringSliceFlag) String() string {
	return f.Name
}

func (f StringSliceFlag) Default() interface{} {
	return f.Value
}

func (f StringSliceFlag) IsOptional() bool {
	return f.Optional
}

type IntFlag struct {
	Name     string
	Usage    string
	EnvVar   string
	Value    int
	Optional bool
}

// TODO: Could this be done more succinctly using embedding?
func (f IntFlag) String() string {
	return f.Name
}

func (f IntFlag) Default() interface{} {
	return f.Value
}

func (f IntFlag) IsOptional() bool {
	return f.Optional
}

type BoolFlag struct {
	Name     string
	Usage    string
	EnvVar   string
	Optional bool
}

// TODO: Could this be done more succinctly using embedding?
func (f BoolFlag) String() string {
	return f.Name
}

func (f BoolFlag) Default() interface{} {
	return false
}

func (f BoolFlag) IsOptional() bool {
	return f.Optional
}
