package amazonec2

import (
	"errors"
)

type region struct {
	AmiId string
}

// Ubuntu 20.04 LTS hvm:ebs-ssd (amd64)
// See https://cloud-images.ubuntu.com/locator/ec2/
var regionDetails map[string]*region = map[string]*region{
	"af-south-1":      {"ami-0866ad1ddbcbab19d"},
	"ap-east-1":       {"ami-06740880eb017a853"},
	"ap-northeast-1":  {"ami-09756a24f95dc6525"},
	"ap-northeast-2":  {"ami-03c920ab98fa7ed2d"},
	"ap-northeast-3":  {"ami-0ff7b5d688fe17fff"},
	"ap-south-1":      {"ami-0f3f4cc1acdeb9971"},
	"ap-south-2":      {"ami-0d0bb69627ce83613"},
	"ap-southeast-1":  {"ami-0095e05a7e9619643"},
	"ap-southeast-2":  {"ami-04491d9c87554d23d"},
	"ap-southeast-3":  {"ami-0171e403912d22753"},
	"ap-southeast-4":  {"ami-0d5f92129ee749caa"},
	"ca-central-1":    {"ami-090de6c2acaf01cc9"},
	"ca-west-1":       {"ami-0a2d74c286a0f6750c"},
	"cn-north-1":      {"ami-066d0aef70143b3c6"},
	"cn-northwest-1":  {"ami-003e0269f2e5df818"},
	"eu-central-1":    {"ami-039e31dd8219f99f7"},
	"eu-central-2":    {"ami-0423ae7c73fa3e8dd"},
	"eu-north-1":      {"ami-097d8c6e5dabbf5e8"},
	"eu-south-1":      {"ami-013522d512a81bf68"},
	"eu-south-2":      {"ami-0564d2758b3f24c3e"},
	"eu-west-1":       {"ami-0d0099f3f21d6b80e"},
	"eu-west-2":       {"ami-0474b5bfa31bac5a7"},
	"eu-west-3":       {"ami-03f0da5df7a0316a4"},
	"il-central-1":    {"ami-064d13b4d06eff594"},
	"me-central-1":    {"ami-0275a75a6935cb83a"},
	"me-south-1":      {"ami-04f82eaceace63346"},
	"sa-east-1":       {"ami-091ebe85e9d554f1d"},
	"us-east-1":       {"ami-0f8b8f874036055b1"},
	"us-east-2":       {"ami-0b1ab4a4995172f25"},
	"us-west-1":       {"ami-0e900b10daaf63cdf"},
	"us-west-2":       {"ami-03e80dc555115a214"},
	"us-gov-east-1":   {"ami-03b3cb35742519ef2"},
	"us-gov-west-1":   {"ami-0a6b0c60f2476df25"},
	"custom-endpoint": {""},
}

func awsRegionsList() []string {
	var list []string

	for k := range regionDetails {
		list = append(list, k)
	}

	return list
}

func validateAwsRegion(region string) (string, error) {
	for _, v := range awsRegionsList() {
		if v == region {
			return region, nil
		}
	}

	return "", errors.New("Invalid region specified")
}
