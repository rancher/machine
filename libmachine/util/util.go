package util

import (
	"net/http"
	"net/url"
	"os"
	"strings"
)

func FindEnvAny(names ...string) string {
	for _, n := range names {
		if val := os.Getenv(n); val != "" {
			return val
		}
	}
	return ""
}

// GetProxyURL returns the URL of the proxy to use for this given hostUrl as indicated by the environment variables
// HTTP_PROXY, HTTPS_PROXY and NO_PROXY (or the lowercase versions thereof).
// HTTPS_PROXY takes precedence over HTTP_PROXY for https requests.
// The hostUrl may be either a complete URL or a "host[:port]", in which case the "http" scheme is assumed.
func GetProxyURL(hostUrl string) (*url.URL, error) {
	req, err := http.NewRequest(http.MethodGet, hostUrl, nil)
	if err != nil {
		return nil, err
	}
	proxy, err := http.ProxyFromEnvironment(req)
	if err != nil {
		return nil, err
	}
	return proxy, nil
}

// SplitArgs splits the given args slice into two slices. The first slice will contain all arguments before the special
// "--" argument separator, and the second will contain all arguments after it.
// For example, if the arguments are
//
//	"./machine host1 host2 -- --driver-flag driver-arg"
//
// then the first slice of arguments will be
//
//	"./machine host1 host2"
//
// and the second slice of arguments will be
//
//	"--driver-flag driver-arg"
func SplitArgs(args []string) ([]string, []string) {
	leftArgs, rightArgs := make([]string, 0), make([]string, 0)
	foundSep := false
	for _, arg := range args {
		if !foundSep {
			leftArgs = append(leftArgs, arg)
		} else if strings.TrimSpace(arg) == "--" {
			foundSep = true
		} else {
			rightArgs = append(rightArgs, arg)
		}
	}

	return leftArgs, rightArgs
}
