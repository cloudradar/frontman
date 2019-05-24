package frontman

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJoinStrings(t *testing.T) {
	assert.Equal(t, []string{"a", "b", "c"}, joinStrings([]string{"a"}, []string{"b", "c"}))
}
