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
	"af-south-1":      {"ami-0f974a103be1a32cc"},
	"ap-northeast-1":  {"ami-09ff2b6ef00accc2e"},
	"ap-northeast-2":  {"ami-0b329fb1f17558744"},
	"ap-northeast-3":  {"ami-0fa06c85437a220f5"},
	"ap-southeast-1":  {"ami-048b4b1ddefe6759f"},
	"ap-southeast-2":  {"ami-052a251c7ca533c26"},
	"ap-southeast-4":  {"ami-01b54c470a1da561d"},
	"ap-south-1":      {"ami-01957c76cce45de38"},
	"ap-south-2":      {"ami-0eaa3ccae04723740"},
	"ap-east-1":       {"ami-0a7893426ebe74a8c"},
	"ca-central-1":    {"ami-095509bf36d02a8e0"},
	"ca-west-1":       {"ami-07cfb3e4b8d29eaf4"},
	"cn-north-1":      {"ami-0592ccadb56e65f8d"},
	"cn-northwest-1":  {"ami-007d0f254ea0f8588"},
	"eu-central-1":    {"ami-0d3905203a039e3b0"},
	"eu-central-2":    {"ami-0e5cf0e302a738bde"},
	"eu-north-1":      {"ami-0803bdfa576dd60c2"},
	"eu-south-1":      {"ami-08a4feb1e48d2f9d8"},
	"eu-south-2":      {"ami-048cc74e15ef972b1"},
	"eu-west-1":       {"ami-0b7fd7bc9c6fb1c78"},
	"eu-west-2":       {"ami-02ead6ecbd926d792"},
	"eu-west-3":       {"ami-0d7b738ade930e24a"},
	"me-south-1":      {"ami-0e53ffff39fa7b5c1"},
	"me-central-1":    {"ami-0bcb1a83b40b4f666"},
	"sa-east-1":       {"ami-03f2389c2526e67bd"},
	"us-east-1":       {"ami-04cc2b0ad9e30a9c8"},
	"us-east-2":       {"ami-02fc6052104add5ae"},
	"us-west-1":       {"ami-07be40433001d2433"},
	"us-west-2":       {"ami-0a62a78cfedc09d76"},
	"us-gov-west-1":   {"ami-0c39aacd1cc8a1ccf"},
	"us-gov-east-1":   {"ami-0dec4096f1af85e9b"},
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
