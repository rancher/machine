package amazonec2

import (
	"errors"
)

type region struct {
	AmiId   string
	SSHUser string
}

// openSUSE Leap 16.0 hvm:ebs-ssd (x86_64), with an Ubuntu 22.04 LTS fallback
// for regions where SUSE does not publish Leap.
// See https://susepubliccloudinfo.suse.com/v1/amazon/images/active.json
// and https://cloud-images.ubuntu.com/locator/ec2/
var regionDetails map[string]*region = map[string]*region{
	"af-south-1":      {"ami-043ec34bd7b4dac54", "ec2-user"},
	"ap-northeast-1":  {"ami-02039b5e5fd4cb133", "ec2-user"},
	"ap-northeast-2":  {"ami-0acb744705faf1eb0", "ec2-user"},
	"ap-northeast-3":  {"ami-0f75afd6ee6043f19", "ec2-user"},
	"ap-southeast-1":  {"ami-0fc1de5c7aa839644", "ec2-user"},
	"ap-southeast-2":  {"ami-0b2c07b0f71191093", "ec2-user"},
	"ap-southeast-4":  {"ami-0a34e5a86c0020716", "ec2-user"},
	"ap-south-1":      {"ami-0efa07633d6c1636d", "ec2-user"},
	"ap-south-2":      {"ami-0c1a24bf4aa90b3ad", "ec2-user"},
	"ap-east-1":       {"ami-039650fd1002020d2", "ec2-user"},
	"ca-central-1":    {"ami-0d01345b7d90631ca", "ec2-user"},
	"ca-west-1":       {"ami-01388a0906fe0008c", "ec2-user"},
	"cn-north-1":      {"ami-0cee61fcc2abc6536", "ubuntu"},
	"cn-northwest-1":  {"ami-063dbdfa885edce48", "ubuntu"},
	"eu-central-1":    {"ami-0d347702534606a35", "ec2-user"},
	"eu-central-2":    {"ami-0ba82ef40306fcb2f", "ubuntu"},
	"eu-north-1":      {"ami-08e2dded5055ab341", "ec2-user"},
	"eu-south-1":      {"ami-0fc18530738e3a3dc", "ec2-user"},
	"eu-south-2":      {"ami-00ccf59845b355398", "ubuntu"},
	"eu-west-1":       {"ami-0c83bf6d22a4cef51", "ec2-user"},
	"eu-west-2":       {"ami-0b9505d4e7132dbf9", "ec2-user"},
	"eu-west-3":       {"ami-08facb981a62454f2", "ec2-user"},
	"me-south-1":      {"ami-065486d3a64fb2f7c", "ec2-user"},
	"me-central-1":    {"ami-05ab10873f5acc36e", "ubuntu"},
	"sa-east-1":       {"ami-0579aede919586cde", "ec2-user"},
	"us-east-1":       {"ami-0d82565d0d235ef73", "ec2-user"},
	"us-east-2":       {"ami-00ea500a732d66b48", "ec2-user"},
	"us-west-1":       {"ami-066d6e6885383abd6", "ec2-user"},
	"us-west-2":       {"ami-043d66434fa3b3779", "ec2-user"},
	"us-gov-west-1":   {"ami-040a15d01bb152ac0", "ubuntu"},
	"us-gov-east-1":   {"ami-093d375659859241e", "ubuntu"},
	"custom-endpoint": {"", ""},
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
