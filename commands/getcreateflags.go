package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"

	"github.com/rancher/machine/libmachine"
	"github.com/rancher/machine/libmachine/drivers/rpc"
	"github.com/rancher/machine/libmachine/log"
	cli "github.com/rancher/machine/libmachine/mcnflag"
)

type fieldType string

const (
	fieldTypeString      = "string"
	fieldTypeBoolean     = "boolean"
	fieldTypeInt         = "integer"
	fieldTypeStringSlice = "stringSlice"
)

type field struct {
	Type        fieldType
	Name        string
	Description string
	Default     any
}

func cmdGetCreateFlags(c CommandLine, _ libmachine.API) error {
	if len(c.Args()) != 0 {
		log.Warnf("extra arguments provided, ignoring...")
	}

	driverName := c.String("driver")
	clientFactory := rpcdriver.NewRPCClientDriverFactory()
	defer clientFactory.Close()

	driver, err := clientFactory.NewRPCClientDriver(driverName, nil)
	if err != nil {
		return err
	}

	var fields []field
	var errs []error
	for _, flag := range driver.GetCreateFlags() {
		if f, err := fieldFromFlag(flag); err != nil {
			errs = append(errs, err)
		} else {
			fields = append(fields, f)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	var out io.Writer = os.Stdout
	if output := c.String("output"); output != "" {
		f, err := os.Create(output)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}

	return json.NewEncoder(out).Encode(fields)
}

func fieldFromFlag(flag cli.Flag) (field, error) {
	switch v := flag.(type) {
	case *cli.StringFlag:
		return field{
			Name:        flag.String(),
			Type:        fieldTypeString,
			Description: v.Usage,
			Default:     v.Default(),
		}, nil
	case *cli.IntFlag:
		return field{
			Name:        flag.String(),
			Type:        fieldTypeInt,
			Description: v.Usage,
			Default:     v.Default(),
		}, nil
	case *cli.BoolFlag:
		return field{
			Name:        flag.String(),
			Type:        fieldTypeBoolean,
			Description: v.Usage,
			Default:     v.Default(),
		}, nil
	case *cli.StringSliceFlag:
		return field{
			Name:        flag.String(),
			Type:        fieldTypeStringSlice,
			Description: v.Usage,
			Default:     v.Default(),
		}, nil
	default:
		return field{}, fmt.Errorf("unknown type of flag %v: %v", flag, reflect.TypeOf(flag))
	}
}
