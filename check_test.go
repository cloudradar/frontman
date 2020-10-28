package frontman

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInProgressChecks(t *testing.T) {

	ipc := newIPC()

	ipc.add("one")
	ipc.add("two")
	assert.Equal(t, true, ipc.isInProgress("one"))
	assert.Equal(t, true, ipc.isInProgress("two"))
	assert.Equal(t, false, ipc.isInProgress("three"))

	ipc.remove("two")
	assert.Equal(t, false, ipc.isInProgress("two"))
}
