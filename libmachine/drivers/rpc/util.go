package rpcdriver

import (
	"os"
	"strconv"
	"strings"

	"github.com/rancher/machine/libmachine/mcnflag"
)

func GetDriverOpts(flags []mcnflag.Flag) *RPCFlags {
	allFlags := GetAllFlags()
	foundFlags := make(map[string]any)

	for _, f := range flags {
		if boolFlag, ok := f.(mcnflag.BoolFlag); ok {
			setFlag(boolFlag.Name, boolFlag.EnvVar, allFlags, foundFlags, toBool)
		}

		if stringFlag, ok := f.(mcnflag.StringFlag); ok {
			setFlag(stringFlag.Name, stringFlag.EnvVar, allFlags, foundFlags, toString)
		}

		if intFlag, ok := f.(mcnflag.IntFlag); ok {
			setFlag(intFlag.Name, intFlag.EnvVar, allFlags, foundFlags, toInt)
		}

		if stringSliceFlag, ok := f.(mcnflag.StringSliceFlag); ok {
			setFlag(stringSliceFlag.Name, stringSliceFlag.EnvVar, allFlags, foundFlags, toStringSlice)
		}
	}

	return &RPCFlags{Values: foundFlags}
}

func toBool(v any) any {
	if boolV, ok := v.(bool); ok {
		return boolV
	}

	return nil
}

func toString(v any) any {
	if stringV, ok := v.(string); ok {
		return stringV
	}

	return nil
}

func toInt(v any) any {
	// If v is already an int, return it.
	if intV, ok := v.(int); ok {
		return intV
	}

	// If v is a string, try converting it into an int.
	if stringV := toString(v); stringV != nil {
		if intV, err := strconv.Atoi(stringV.(string)); err != nil {
			return intV
		}
	}

	return nil
}

func toStringSlice(v any) any {
	// If v is a string, slice it by comma.
	if stringV, ok := v.(string); ok {
		return strings.Split(stringV, ",")
	}

	return nil
}

func setFlag(
	name, envvar string,
	allFlags map[string]any,
	foundFlags map[string]any,
	convertFunc func(any) any,
) {
	if v, ok := allFlags[name]; ok {
		if result := convertFunc(v); result != nil {
			foundFlags[name] = result
		}
		return
	}

	if envvar != "" {
		if v, ok := os.LookupEnv(envvar); ok {
			if result := convertFunc(v); result != nil {
				foundFlags[name] = result
			}
		}
	}
}

func GetAllFlags() map[string]any {
	flagValues := make(map[string]any)
	for i, arg := range os.Args {
		if !strings.HasPrefix(arg, "-") {
			continue
		}

		trimmedFlag := strings.TrimLeft(arg, "-")
		flagParts := strings.Split(trimmedFlag, "=")
		if len(flagParts) > 1 {
			flagValues[flagParts[0]] = flagParts[1]
		} else if len(os.Args) > i+1 && !strings.HasPrefix(os.Args[i+1], "-") {
			flagValues[trimmedFlag] = os.Args[i+1]
		} else {
			flagValues[trimmedFlag] = true
		}
	}

	return flagValues
}
