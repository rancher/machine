package amazonec2

import (
	"errors"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/stretchr/testify/mock"
)

type fakeEC2 struct {
	*ec2.EC2
}

type errorProvider struct{}

func (p *errorProvider) Retrieve() (credentials.Value, error) {
	return credentials.Value{}, errors.New("bad credentials")
}

func (p *errorProvider) IsExpired() bool {
	return true
}

type okProvider struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
}

func (p *okProvider) Retrieve() (credentials.Value, error) {
	return credentials.Value{
		AccessKeyID:     p.accessKeyID,
		SecretAccessKey: p.secretAccessKey,
		SessionToken:    p.sessionToken,
	}, nil
}

func (p *okProvider) IsExpired() bool {
	return true
}

type fallbackCredentials struct{}

func (c *fallbackCredentials) Credentials() *credentials.Credentials {
	return credentials.NewStaticCredentials("fallback_access", "fallback_secret", "fallback_token")
}

func NewValidAwsCredentials() awsCredentials {
	return &fallbackCredentials{}
}

type errorFallbackCredentials struct{}

func (c *errorFallbackCredentials) Credentials() *credentials.Credentials {
	return credentials.NewCredentials(&errorProvider{})
}

func NewErrorAwsCredentials() awsCredentials {
	return &errorFallbackCredentials{}
}

type errorCredentialsProvider struct{}

func (c *errorCredentialsProvider) NewStaticProvider(id, secret, token string) credentials.Provider {
	return &errorProvider{}
}

type fakeEC2WithDescribe struct {
	*fakeEC2
	output *ec2.DescribeAccountAttributesOutput
	err    error
}

func (f *fakeEC2WithDescribe) DescribeAccountAttributes(input *ec2.DescribeAccountAttributesInput) (*ec2.DescribeAccountAttributesOutput, error) {
	return f.output, f.err
}

type fakeEC2WithLogin struct {
	*fakeEC2
}

func (f *fakeEC2WithLogin) DescribeAccountAttributes(input *ec2.DescribeAccountAttributesInput) (*ec2.DescribeAccountAttributesOutput, error) {
	defaultVpc := "default-vpc"
	vpcName := "vpc-9999"

	return &ec2.DescribeAccountAttributesOutput{
		AccountAttributes: []*ec2.AccountAttribute{
			{
				AttributeName: &defaultVpc,
				AttributeValues: []*ec2.AccountAttributeValue{
					{AttributeValue: &vpcName},
				},
			},
		},
	}, nil
}

func (f *fakeEC2WithLogin) DescribeImages(input *ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error) {
	if len(input.ImageIds) == 0 || input.ImageIds[0] == nil {
		return nil, errors.New("bad input")
	}
	amiID := *input.ImageIds[0]
	switch amiID {
	case defaultAmiId, "ami-0c43b23f011ba5061": // two Ubuntu images
		return &ec2.DescribeImagesOutput{Images: []*ec2.Image{
			&ec2.Image{RootDeviceName: aws.String("/dev/sda1")},
		}}, nil
	case "ami-0eeb1ef502d7b850d": // Fedora CoreOS image
		return &ec2.DescribeImagesOutput{Images: []*ec2.Image{
			&ec2.Image{RootDeviceName: aws.String("/dev/xvda")},
		}}, nil
	default:
		return nil, errors.New("no mock for input")
	}
}

type fakeEC2SecurityGroupTestRecorder struct {
	*fakeEC2
	mock.Mock
}

func (f *fakeEC2SecurityGroupTestRecorder) DescribeSecurityGroups(input *ec2.DescribeSecurityGroupsInput) (*ec2.DescribeSecurityGroupsOutput, error) {
	result := f.Called(input)
	err := result.Error(1)
	value, ok := result.Get(0).(*ec2.DescribeSecurityGroupsOutput)
	if !ok && err == nil {
		return nil, errors.New("type assertion to DescribeSecurityGroupsOutput failed")
	}
	return value, err
}

func (f *fakeEC2SecurityGroupTestRecorder) CreateSecurityGroup(input *ec2.CreateSecurityGroupInput) (*ec2.CreateSecurityGroupOutput, error) {
	result := f.Called(input)
	err := result.Error(1)
	value, ok := result.Get(0).(*ec2.CreateSecurityGroupOutput)
	if !ok && err == nil {
		return nil, errors.New("type assertion to CreateSecurityGroupOutput failed")
	}
	return value, err
}

func (f *fakeEC2SecurityGroupTestRecorder) AuthorizeSecurityGroupIngress(input *ec2.AuthorizeSecurityGroupIngressInput) (*ec2.AuthorizeSecurityGroupIngressOutput, error) {
	result := f.Called(input)
	err := result.Error(1)
	value, ok := result.Get(0).(*ec2.AuthorizeSecurityGroupIngressOutput)
	if !ok && err == nil {
		return nil, errors.New("type assertion to AuthorizeSecurityGroupIngressInput failed")
	}
	return value, err
}

func (f *fakeEC2SecurityGroupTestRecorder) CreateTags(input *ec2.CreateTagsInput) (*ec2.CreateTagsOutput, error) {
	result := f.Called(input)
	err := result.Error(1)
	value, ok := result.Get(0).(*ec2.CreateTagsOutput)
	if !ok && err == nil {
		return nil, errors.New("type assertion to CreateTagsOutput failed")
	}
	return value, err
}

func NewTestDriver() *Driver {
	driver := NewDriver("machineFoo", "path")
	driver.clientFactory = func() Ec2Client {
		return &fakeEC2{}
	}
	return driver
}

func NewCustomTestDriver(ec2Client Ec2Client) *Driver {
	driver := NewDriver("machineFoo", "path")
	driver.clientFactory = func() Ec2Client {
		return ec2Client
	}
	return driver
}
