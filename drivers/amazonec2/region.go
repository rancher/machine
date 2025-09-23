package amazonec2

import (
	"errors"
)

type region struct {
	AmiId string
}

// Ubuntu 22.04 LTS hvm:ebs-ssd (amd64)
// See https://cloud-images.ubuntu.com/locator/ec2/
var regionDetails map[string]*region = map[string]*region{
	"af-south-1":      {"ami-041bbaef049568980"},
	"ap-northeast-1":  {"ami-08cc96be4321e5b1f"},
	"ap-northeast-2":  {"ami-01e69ea1a3e0010f9"},
	"ap-northeast-3":  {"ami-0f14d4518c5e11193"},
	"ap-southeast-1":  {"ami-0ee022cdf4828fb72"},
	"ap-southeast-2":  {"ami-0df7505ae337f9e56"},
	"ap-southeast-4":  {"ami-0961cde071a13cfcf"},
	"ap-south-1":      {"ami-0114b36a18ddfaa28"},
	"ap-south-2":      {"ami-066d98478cd8e4c77"},
	"ap-east-1":       {"ami-0da677a59bd878935"},
	"ca-central-1":    {"ami-0c28f754c18c566ea"},
	"ca-west-1":       {"ami-050e498a568657807"},
	"cn-north-1":      {"ami-0cee61fcc2abc6536"},
	"cn-northwest-1":  {"ami-063dbdfa885edce48"},
	"eu-central-1":    {"ami-0a43b9fc420cabb27"},
	"eu-central-2":    {"ami-0ba82ef40306fcb2f"},
	"eu-north-1":      {"ami-0d4a39b59c9b7a755"},
	"eu-south-1":      {"ami-0470471c569217367"},
	"eu-south-2":      {"ami-00ccf59845b355398"},
	"eu-west-1":       {"ami-0c6d91e4a58c413a9"},
	"eu-west-2":       {"ami-065908f87471c0a91"},
	"eu-west-3":       {"ami-03339502479ac056b"},
	"me-south-1":      {"ami-0d637f6739f30a48c"},
	"me-central-1":    {"ami-05ab10873f5acc36e"},
	"sa-east-1":       {"ami-050efed1b88ba70b4"},
	"us-east-1":       {"ami-013b3de8a8fa9b39f"},
	"us-east-2":       {"ami-024adb4f8af4c9df2"},
	"us-west-1":       {"ami-0b03b9afed756bb4b"},
	"us-west-2":       {"ami-09a13b25443518b29"},
	"us-gov-west-1":   {"ami-040a15d01bb152ac0"},
	"us-gov-east-1":   {"ami-093d375659859241e"},
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

	return "", errors.New("invalid region specified")
}
