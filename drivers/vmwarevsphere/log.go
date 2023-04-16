package vmwarevsphere

/* NOTE: This file was cribbed from
https://github.com/vmware/govmomi/blob/d9bfec25def5ed85e39f2cd337ffff7efad22864/vim25/debug/log.go
It differs in that it replaces the use of fmt.Fprint with fmt.Fprintln which seems to resolve hanging.
See https://github.com/vmware/govmomi/issues/3099 for more context. If/when the PR that is associated with that issue is
merged and a new govmomi release is cut, we can remove this file.
*/

import (
	"fmt"
	"io"
	"os"

	"github.com/vmware/govmomi/vim25/debug"
)

type LogWriterCloser struct {
}

func NewLogWriterCloser() *LogWriterCloser {
	return &LogWriterCloser{}
}

func (lwc *LogWriterCloser) Write(p []byte) (n int, err error) {
	return fmt.Fprintln(os.Stderr, string(debug.Scrub(p)))
}

func (lwc *LogWriterCloser) Close() error {
	return nil
}

type LogProvider struct {
}

func (s *LogProvider) NewFile(p string) io.WriteCloser {
	if _, err := fmt.Fprintln(os.Stderr, p); err != nil {
		return nil
	}
	return NewLogWriterCloser()
}

func (s *LogProvider) Flush() {
}
