package google

import (
	"testing"

	"github.com/rancher/wrangler/v3/pkg/name"
	"github.com/stretchr/testify/assert"
	raw "google.golang.org/api/compute/v1"
)

func TestAllTagTypes(t *testing.T) {
	tags := parseTags(&Driver{
		OpenPorts: []string{
			"one",
			"two",
			"three",
		},
		Tags: "four,five,six",
	}, &ComputeUtil{
		externalFirewallRulePrefix: "outside",
		internalFirewallRulePrefix: "inside",
	})

	assert.Equal(t, []string{
		"four",
		"five",
		"six",
		name.SafeConcatName("inside", internalFirewallRuleSuffix),
		name.SafeConcatName("outside", externalFirewallRuleSuffix),
	}, tags)
}

func TestInternalOnlyTag(t *testing.T) {
	tags := parseTags(
		&Driver{},
		&ComputeUtil{
			internalFirewallRulePrefix: "inside",
		})

	assert.Equal(t, []string{name.SafeConcatName("inside", internalFirewallRuleSuffix)}, tags)
}

func TestExternalOnlyTag(t *testing.T) {
	tags := parseTags(&Driver{
		OpenPorts: []string{
			"123",
		},
	}, &ComputeUtil{
		externalFirewallRulePrefix: "outside",
		openPorts: []string{
			"123",
		},
	})

	assert.Equal(t, []string{name.SafeConcatName("outside", externalFirewallRuleSuffix)}, tags)
}

func TestPortsUsed(t *testing.T) {
	var tests = []struct {
		description   string
		computeUtil   *ComputeUtil
		expectedPorts []string
		expectedError error
	}{
		{"use swarm port", &ComputeUtil{SwarmMaster: true, SwarmHost: "tcp://host:3376"}, []string{"3376/tcp"}, nil},
		{"use non default swarm port", &ComputeUtil{SwarmMaster: true, SwarmHost: "tcp://host:4242"}, []string{"4242/tcp"}, nil},
		{"include additional ports", &ComputeUtil{openPorts: []string{"80", "2377/udp"}}, []string{"80/tcp", "2377/udp"}, nil},
	}

	for _, test := range tests {
		ports, err := test.computeUtil.portsUsed()

		assert.Equal(t, test.expectedPorts, ports)
		assert.Equal(t, test.expectedError, err)
	}
}

func TestMissingOpenedPorts(t *testing.T) {
	var tests = []struct {
		description     string
		allowed         []*raw.FirewallAllowed
		ports           []string
		expectedMissing map[string][]string
	}{
		{"no port opened", []*raw.FirewallAllowed{}, []string{"2376"}, map[string][]string{"tcp": {"2376"}}},
		{"docker port opened", []*raw.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"2376"}}}, []string{"2376"}, map[string][]string{}},
		{"missing swarm port", []*raw.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"2376"}}}, []string{"2376", "3376"}, map[string][]string{"tcp": {"3376"}}},
		{"missing docker port", []*raw.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"3376"}}}, []string{"2376", "3376"}, map[string][]string{"tcp": {"2376"}}},
		{"both ports opened", []*raw.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"2376", "3376"}}}, []string{"2376", "3376"}, map[string][]string{}},
		{"more ports opened", []*raw.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"2376", "3376", "22", "1024-2048"}}}, []string{"2376", "3376"}, map[string][]string{}},
		{"additional missing", []*raw.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"2376", "2377/tcp"}}}, []string{"2377/udp", "80/tcp", "2376"}, map[string][]string{"tcp": {"80"}, "udp": {"2377"}}},
	}

	for _, test := range tests {
		firewall := &raw.Firewall{Allowed: test.allowed}

		missingPorts := missingOpenedPorts(firewall, test.ports)

		assert.Equal(t, test.expectedMissing, missingPorts, test.description)
	}
}

func TestParseLabels(t *testing.T) {
	var tests = []struct {
		name     string
		labels   string
		expected map[string]string
	}{
		{
			"empty",
			"",
			map[string]string{},
		},
		{
			"valid label",
			"one,two",
			map[string]string{
				"one": "two",
			},
		},
		{
			"valid labels",
			"one,two,three,four",
			map[string]string{
				"one":   "two",
				"three": "four",
			},
		},
		{
			"invalid format",
			"one,two,three",
			map[string]string{
				"one": "two",
			},
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseLabels(tt.labels))
		})
	}
}
