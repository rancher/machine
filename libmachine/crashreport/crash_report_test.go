package crashreport

import (
	"testing"

	"os"
	"path/filepath"

	"github.com/bugsnag/bugsnag-go"
	"github.com/stretchr/testify/assert"
)

func TestFileIsNotReadWhenNotExisting(t *testing.T) {
	metaData := bugsnag.MetaData{}
	addFile("not existing", &metaData)
	assert.Empty(t, metaData)
}

func TestRead(t *testing.T) {
	metaData := bugsnag.MetaData{}
	content := "foo\nbar\nqix\n"
	fileName := createTempFile(t, content)
	defer os.Remove(fileName)
	addFile(fileName, &metaData)
	assert.Equal(t, "foo\nbar\nqix\n", metaData["logfile"][filepath.Base(fileName)])
}

func createTempFile(t *testing.T, content string) string {
	file, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file.Name(), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return file.Name()
}
