package azure

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnmarshalJSON(t *testing.T) {
	driver := NewDriver("", "").(*Driver)

	// Unmarhsal driver configuration from JSON, envvars, and args.
	assert.NoError(t, os.Setenv("AZURE_ENVIRONMENT", "test env"))
	assert.NoError(t, os.Setenv("AZURE_CLIENT_SECRET", "test client secret"))
	os.Args = append(os.Args, []string{"--azure-subscription-id", "test sub ID", "--azure-client-id", "test client ID"}...)

	driverBytes, err := json.Marshal(driver)
	assert.NoError(t, err)
	assert.NoError(t, json.Unmarshal(driverBytes, driver))

	// Make sure that config has been pulled in from envvars and args.
	assert.Equal(t, "test env", driver.Environment)
	assert.Equal(t, "test client secret", driver.ClientSecret)
	assert.Equal(t, "test client ID", driver.ClientID)
	assert.Equal(t, "test sub ID", driver.SubscriptionID)
}
