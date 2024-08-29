package amazonec2

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/rancher/machine/commands/commandstest"
	"github.com/rancher/machine/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	testSSHPort    = int64(22)
	testDockerPort = int64(2376)
)

var (
	rancherSecurityGroup = &ec2.SecurityGroup{
		GroupName: aws.String(defaultSecurityGroup),
		GroupId:   aws.String("12345"),
		VpcId:     aws.String("12345"),
		Tags: []*ec2.Tag{
			{
				Key:   aws.String(machineSecurityGroupName),
				Value: aws.String("test"),
			},
		},
	}

	/* This test resource should be used in tests that set their own IpPermissions */
	securityGroup = &ec2.SecurityGroup{
		GroupName: aws.String("test-group"),
		GroupId:   aws.String("12345"),
		VpcId:     aws.String("12345"),
	}

	/* This test resource should only be used in tests that do not update IpPermissions */
	securityGroupNoIpPermissions = &ec2.SecurityGroup{
		GroupName:     aws.String(defaultSecurityGroup),
		GroupId:       aws.String("12345"),
		VpcId:         aws.String("12345"),
		IpPermissions: []*ec2.IpPermission{},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String(machineSecurityGroupName),
				Value: aws.String("test"),
			},
		},
	}
)

func TestUnmarshalJSON(t *testing.T) {
	// Create a new driver and make sure its function fields aren't nil.
	driver := NewDriver("", "")
	assert.NotNil(t, driver.awsCredentialsFactory)
	assert.NotNil(t, driver.clientFactory)

	// Unmarhsal driver configuration from JSON, envvars, and args.
	assert.NoError(t, os.Setenv("AWS_ACCESS_KEY_ID", "test key ID"))
	os.Args = append(os.Args, []string{"--amazonec2-secret-key", "test key"}...)

	driverBytes, err := json.Marshal(driver)
	assert.NoError(t, err)
	assert.NoError(t, json.Unmarshal(driverBytes, driver))

	// Make sure the function fields on the have not been changed to nil and that
	// config has been pulled in from envvars and args.
	assert.NotNil(t, driver.awsCredentialsFactory)
	assert.NotNil(t, driver.clientFactory)
	assert.Equal(t, "test key ID", driver.AccessKey)
	assert.Equal(t, "test key", driver.SecretKey)
}

func TestConfigureSecurityGroupPermissionsEmpty(t *testing.T) {
	driver := NewTestDriver()

	perms, err := driver.configureSecurityGroupPermissions(securityGroup)

	assert.Nil(t, err)
	assert.Empty(t, perms)
}

func TestRancherSecurityGroupPermissions(t *testing.T) {
	driver := NewTestDriver()

	perms, err := driver.configureSecurityGroupPermissions(rancherSecurityGroup)

	assert.Nil(t, err)
	assert.Len(t, perms, 17)
	assert.Equal(t, testSSHPort, *perms[0].FromPort)
}

func TestConfigureSecurityGroupPermissionsDockerAndSsh(t *testing.T) {
	driver := NewTestDriver()
	group := securityGroup
	group.IpPermissions = []*ec2.IpPermission{
		{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int64(testSSHPort),
			ToPort:     aws.Int64(testSSHPort),
		},
		{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int64(testDockerPort),
			ToPort:     aws.Int64(testDockerPort),
		},
	}

	perms, err := driver.configureSecurityGroupPermissions(group)

	assert.Nil(t, err)
	assert.Empty(t, perms)
}

func TestConfigureSecurityGroupPermissionsSkipReadOnly(t *testing.T) {
	driver := NewTestDriver()
	driver.SecurityGroupReadOnly = true
	perms, err := driver.configureSecurityGroupPermissions(securityGroupNoIpPermissions)

	assert.Nil(t, err)
	assert.Len(t, perms, 0)
}

func TestConfigureSecurityGroupPermissionsInvalidOpenPorts(t *testing.T) {
	driver := NewTestDriver()
	driver.OpenPorts = []string{"2222/tcp", "abc1"}
	perms, err := driver.configureSecurityGroupPermissions(securityGroupNoIpPermissions)

	assert.Error(t, err)
	assert.Nil(t, perms)
}

func TestValidateAwsRegionValid(t *testing.T) {
	regions := []string{"eu-west-1", "eu-central-1"}

	for _, region := range regions {
		validatedRegion, err := validateAwsRegion(region)

		assert.NoError(t, err)
		assert.Equal(t, region, validatedRegion)
	}
}

func TestValidateAwsRegionInvalid(t *testing.T) {
	regions := []string{"eu-central-3"}

	for _, region := range regions {
		_, err := validateAwsRegion(region)

		assert.EqualError(t, err, "Invalid region specified")
	}
}

func TestFindDefaultVPC(t *testing.T) {
	driver := NewDriver("machineFoo", "path")
	driver.clientFactory = func() Ec2Client {
		return &fakeEC2WithLogin{}
	}

	vpc, err := driver.getDefaultVPCId()

	assert.Equal(t, "vpc-9999", vpc)
	assert.NoError(t, err)
}

func TestDefaultVPCIsMissing(t *testing.T) {
	driver := NewDriver("machineFoo", "path")
	driver.clientFactory = func() Ec2Client {
		return &fakeEC2WithDescribe{
			output: &ec2.DescribeAccountAttributesOutput{
				AccountAttributes: []*ec2.AccountAttribute{},
			},
		}
	}

	vpc, err := driver.getDefaultVPCId()

	assert.EqualError(t, err, "No default-vpc attribute")
	assert.Empty(t, vpc)
}

func TestGetRegionZoneForDefaultEndpoint(t *testing.T) {
	driver := NewCustomTestDriver(&fakeEC2WithLogin{})
	driver.awsCredentialsFactory = NewValidAwsCredentials
	options := &commandstest.FakeFlagger{
		Data: map[string]interface{}{
			"name":             "test",
			"amazonec2-region": "us-east-1",
			"amazonec2-zone":   "e",
		},
	}

	err := driver.SetConfigFromFlags(options)

	regionZone := driver.getRegionZone()

	assert.Equal(t, "us-east-1e", regionZone)
	assert.NoError(t, err)
}

func TestGetRegionZoneForCustomEndpoint(t *testing.T) {
	driver := NewCustomTestDriver(&fakeEC2WithLogin{})
	driver.awsCredentialsFactory = NewValidAwsCredentials
	options := &commandstest.FakeFlagger{
		Data: map[string]interface{}{
			"name":               "test",
			"amazonec2-endpoint": "https://someurl",
			"amazonec2-region":   "custom-endpoint",
			"amazonec2-zone":     "custom-zone",
		},
	}

	err := driver.SetConfigFromFlags(options)

	regionZone := driver.getRegionZone()

	assert.Equal(t, "custom-zone", regionZone)
	assert.NoError(t, err)
}

func TestDescribeAccountAttributeFails(t *testing.T) {
	driver := NewDriver("machineFoo", "path")
	driver.clientFactory = func() Ec2Client {
		return &fakeEC2WithDescribe{
			err: errors.New("Not Found"),
		}
	}

	vpc, err := driver.getDefaultVPCId()

	assert.EqualError(t, err, "Not Found")
	assert.Empty(t, vpc)
}

func TestAwsCredentialsAreRequired(t *testing.T) {
	driver := NewTestDriver()
	driver.awsCredentialsFactory = NewErrorAwsCredentials

	options := &commandstest.FakeFlagger{
		Data: map[string]interface{}{
			"name":             "test",
			"amazonec2-region": "us-east-1",
			"amazonec2-zone":   "e",
		},
	}

	err := driver.SetConfigFromFlags(options)
	assert.Equal(t, err, errorMissingCredentials)
}

func TestValidAwsCredentialsAreAccepted(t *testing.T) {
	driver := NewCustomTestDriver(&fakeEC2WithLogin{})
	driver.awsCredentialsFactory = NewValidAwsCredentials
	options := &commandstest.FakeFlagger{
		Data: map[string]interface{}{
			"name":             "test",
			"amazonec2-region": "us-east-1",
			"amazonec2-zone":   "e",
		},
	}

	err := driver.SetConfigFromFlags(options)
	assert.NoError(t, err)
}

func TestEndpointIsMandatoryWhenSSLDisabled(t *testing.T) {
	driver := NewTestDriver()
	driver.awsCredentialsFactory = NewValidAwsCredentials
	options := &commandstest.FakeFlagger{
		Data: map[string]interface{}{
			"name":                         "test",
			"amazonec2-access-key":         "foobar",
			"amazonec2-region":             "us-east-1",
			"amazonec2-zone":               "e",
			"amazonec2-insecure-transport": true,
		},
	}

	err := driver.SetConfigFromFlags(options)

	assert.Equal(t, err, errorDisableSSLWithoutCustomEndpoint)
}

var values = []string{
	"bob",
	"jake",
	"jill",
}

var pointerSliceTests = []struct {
	input    []string
	expected []*string
}{
	{[]string{}, []*string{}},
	{[]string{values[1]}, []*string{&values[1]}},
	{[]string{values[0], values[2], values[2]}, []*string{&values[0], &values[2], &values[2]}},
}

func TestMakePointerSlice(t *testing.T) {
	for _, tt := range pointerSliceTests {
		actual := makePointerSlice(tt.input)
		assert.Equal(t, tt.expected, actual)
	}
}

var securityGroupNameTests = []struct {
	groupName  string
	groupNames []string
	expected   []string
}{
	{groupName: "bob", expected: []string{"bob"}},
	{groupNames: []string{"bill"}, expected: []string{"bill"}},
	{groupName: "bob", groupNames: []string{"bill"}, expected: []string{"bob", "bill"}},
}

func TestMergeSecurityGroupName(t *testing.T) {
	for _, tt := range securityGroupNameTests {
		d := Driver{SecurityGroupName: tt.groupName, SecurityGroupNames: tt.groupNames}
		assert.Equal(t, tt.expected, d.securityGroupNames())
	}
}

var securityGroupIdTests = []struct {
	groupId  string
	groupIds []string
	expected []string
}{
	{groupId: "id", expected: []string{"id"}},
	{groupIds: []string{"id"}, expected: []string{"id"}},
	{groupId: "id1", groupIds: []string{"id2"}, expected: []string{"id1", "id2"}},
}

func TestMergeSecurityGroupId(t *testing.T) {
	for _, tt := range securityGroupIdTests {
		d := Driver{SecurityGroupId: tt.groupId, SecurityGroupIds: tt.groupIds}
		assert.Equal(t, tt.expected, d.securityGroupIds())
	}
}

func matchGroupLookup(expected []string) interface{} {
	return func(input *ec2.DescribeSecurityGroupsInput) bool {
		actual := []string{}
		for _, filter := range input.Filters {
			if *filter.Name == "group-name" {
				for _, groupName := range filter.Values {
					actual = append(actual, *groupName)
				}
			}
		}
		return reflect.DeepEqual(expected, actual)
	}
}

func ipPermission(port int64) *ec2.IpPermission {
	return &ec2.IpPermission{
		FromPort:   aws.Int64(port),
		ToPort:     aws.Int64(port),
		IpProtocol: aws.String("tcp"),
		IpRanges:   []*ec2.IpRange{{CidrIp: aws.String(ipRange)}},
	}
}

func TestConfigureSecurityGroupsEmpty(t *testing.T) {
	recorder := fakeEC2SecurityGroupTestRecorder{}

	driver := NewCustomTestDriver(&recorder)
	err := driver.configureSecurityGroups([]string{})

	assert.Nil(t, err)
	recorder.AssertExpectations(t)
}

func TestConfigureSecurityGroupsMixed(t *testing.T) {
	groups := []string{"existingGroup", "newGroup"}
	recorder := fakeEC2SecurityGroupTestRecorder{}

	// First, a check is made for which groups already exist.
	initialLookupResult := ec2.DescribeSecurityGroupsOutput{SecurityGroups: []*ec2.SecurityGroup{
		{
			GroupName:     aws.String("existingGroup"),
			GroupId:       aws.String("existingGroupId"),
			IpPermissions: []*ec2.IpPermission{ipPermission(testSSHPort)},
		},
	}}
	recorder.On("DescribeSecurityGroups", mock.MatchedBy(matchGroupLookup(groups))).Return(
		&initialLookupResult, nil)

	// The new security group is created.
	recorder.On("CreateSecurityGroup", &ec2.CreateSecurityGroupInput{
		GroupName:   aws.String("newGroup"),
		Description: aws.String("Rancher Nodes"),
		VpcId:       aws.String(""),
	}).Return(
		&ec2.CreateSecurityGroupOutput{GroupId: aws.String("newGroupId")}, nil)

	// Ensuring the new security group exists.
	postCreateLookupResult := ec2.DescribeSecurityGroupsOutput{SecurityGroups: []*ec2.SecurityGroup{
		{
			GroupName: aws.String("newGroup"),
			GroupId:   aws.String("newGroupId"),
		},
	}}
	recorder.On("DescribeSecurityGroups",
		&ec2.DescribeSecurityGroupsInput{GroupIds: []*string{aws.String("newGroupId")}}).Return(
		&postCreateLookupResult, nil)

	recorder.On("CreateTags", &ec2.CreateTagsInput{
		Tags: []*ec2.Tag{
			{
				Key:   aws.String(machineTag),
				Value: aws.String(version.Version),
			},
		},
		Resources: []*string{aws.String("newGroupId")},
	}).Return(&ec2.CreateTagsOutput{}, nil)

	driver := NewCustomTestDriver(&recorder)
	err := driver.configureSecurityGroups(groups)

	assert.Nil(t, err)
	recorder.AssertExpectations(t)
}

func TestConfigureSecurityGroupsErrLookupExist(t *testing.T) {
	groups := []string{"group"}
	recorder := fakeEC2SecurityGroupTestRecorder{}

	lookupExistErr := errors.New("lookup failed")
	recorder.On("DescribeSecurityGroups", mock.MatchedBy(matchGroupLookup(groups))).Return(
		nil, lookupExistErr)

	driver := NewCustomTestDriver(&recorder)
	err := driver.configureSecurityGroups(groups)

	assert.Exactly(t, lookupExistErr, err)
	recorder.AssertExpectations(t)
}

func TestBase64UserDataIsEmptyIfNoFileProvided(t *testing.T) {
	driver := NewTestDriver()

	userdata, err := driver.Base64UserData()

	assert.NoError(t, err)
	assert.Empty(t, userdata)
}

func TestBase64UserDataGeneratesErrorIfFileNotFound(t *testing.T) {
	dir, err := os.MkdirTemp("", "awsuserdata")
	assert.NoError(t, err, "Unable to create temporary directory.")

	defer os.RemoveAll(dir)

	userdataPath := filepath.Join(dir, "does-not-exist.yml")

	driver := NewTestDriver()
	driver.UserDataFile = userdataPath

	_, udErr := driver.Base64UserData()
	assert.Equal(t, udErr, errorReadingUserData)
}

func TestBase64UserDataIsCorrectWhenFileProvided(t *testing.T) {
	dir, err := os.MkdirTemp("", "awsuserdata")
	assert.NoError(t, err, "Unable to create temporary directory.")

	defer os.RemoveAll(dir)

	userdataPath := filepath.Join(dir, "test-userdata.yml")

	content := []byte("#cloud-config\nhostname: userdata-test\nfqdn: userdata-test.amazonec2.driver\n")
	contentBase64 := "I2Nsb3VkLWNvbmZpZwpob3N0bmFtZTogdXNlcmRhdGEtdGVzdApmcWRuOiB1c2VyZGF0YS10ZXN0LmFtYXpvbmVjMi5kcml2ZXIK"

	err = os.WriteFile(userdataPath, content, 0666)
	assert.NoError(t, err, "Unable to create temporary userdata file.")

	driver := NewTestDriver()
	driver.UserDataFile = userdataPath

	userdata, udErr := driver.Base64UserData()

	assert.NoError(t, udErr)
	assert.Equal(t, contentBase64, userdata)
}

func TestDefaultAMI(t *testing.T) {
	driver := NewCustomTestDriver(&fakeEC2WithLogin{})

	err := driver.checkAMI()

	assert.Equal(t, "/dev/sda1", driver.DeviceName)
	assert.NoError(t, err)
}

func TestRootDeviceName(t *testing.T) {
	driver := NewCustomTestDriver(&fakeEC2WithLogin{})
	driver.AMI = "ami-0eeb1ef502d7b850d" // Fedora CoreOS image

	err := driver.checkAMI()

	assert.Equal(t, "/dev/xvda", driver.DeviceName)
	assert.NoError(t, err)
}

func TestInvalidAMI(t *testing.T) {
	driver := NewCustomTestDriver(&fakeEC2WithLogin{})
	driver.AMI = "ami-000" // Invalid AMI

	err := driver.checkAMI()

	assert.Error(t, err)
}
