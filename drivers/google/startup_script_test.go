package google

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartupScriptRunsCloudConfig(t *testing.T) {
	if _, err := exec.LookPath("cloud-init"); err == nil {
		t.Skip("the script is a no-op where cloud-init is installed")
	}
	dir := t.TempDir()
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write([]byte("echo \"it's ran\" > " + dir + "/out\n"))
	require.NoError(t, w.Close())

	userdata := `#cloud-config
write_files:
  - path: ` + dir + `/sub/install.sh
    encoding: gzip+b64
    permissions: "0600"
    content: ` + base64.StdEncoding.EncodeToString(gz.Bytes()) + `
runcmd:
  - "false"
  - sh ` + dir + `/sub/install.sh
  - [touch, "` + dir + `/with space"]
`
	script, err := startupScript(userdata)
	require.NoError(t, err)
	script = strings.ReplaceAll(script, startupScriptDoneFile, dir+"/done")

	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	require.NoError(t, err, string(out))

	got, err := os.ReadFile(filepath.Join(dir, "out"))
	require.NoError(t, err)
	assert.Equal(t, "it's ran\n", string(got))
	info, err := os.Stat(filepath.Join(dir, "sub/install.sh"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	assert.FileExists(t, filepath.Join(dir, "with space"))

	// A second boot must not run the userdata again.
	require.NoError(t, os.Remove(filepath.Join(dir, "out")))
	require.NoError(t, exec.Command("sh", "-c", script).Run())
	assert.NoFileExists(t, filepath.Join(dir, "out"))
}

func TestStartupScriptShellUserdata(t *testing.T) {
	script, err := startupScript("#!/bin/bash\necho hi\n")
	require.NoError(t, err)
	assert.Contains(t, script, "#!/bin/bash\necho hi\nRANCHER_MACHINE_EOF\n")
}
