package dshl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScope(t *testing.T) {
	scope1 := &Scope{}
	scope1.Set("key", "value")
	assert.Equal(t, "value", scope1.Get("key"))

	scope2 := scope1.Scope()
	assert.Equal(t, "value", scope2.Get("key"))
	scope2.Set("key", "value2")
	assert.Equal(t, "value2", scope2.Get("key"))

	scope3 := scope2.Scope()
	assert.Equal(t, "value2", scope3.Get("key"))
	scope3.Assign("key", "value3")
	assert.Equal(t, "value3", scope3.Get("key"))
	assert.Equal(t, "value3", scope2.Get("key"))
}
