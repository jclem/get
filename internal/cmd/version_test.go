package cmd_test

import (
	"bytes"
	"testing"

	cmdpkg "github.com/jclem/get/internal/cmd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionCmd(t *testing.T) {
	t.Parallel()

	cmd := cmdpkg.NewVersionCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	require.NoError(t, err)

	output := out.String()
	assert.Contains(t, output, cmdpkg.Version)
}
