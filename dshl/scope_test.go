package dshl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScope(t *testing.T) {
	scope1 := &Scope{}
	scope1.Set("key", "value")
	assert.Equal(t, "value", scope1.Get("key"))
	assert.Equal(t, map[string]interface{}{"key": "value"}, scope1.All())

	scope2 := scope1.Child()
	assert.Equal(t, "value", scope2.Get("key"))
	assert.Equal(t, map[string]interface{}{"key": "value"}, scope2.All())
	scope2.Set("key", "value2")
	assert.Equal(t, "value2", scope2.Get("key"))
	assert.Equal(t, map[string]interface{}{"key": "value2"}, scope2.All())

	scope3 := scope2.Child()
	assert.Equal(t, "value2", scope3.Get("key"))
	assert.Equal(t, map[string]interface{}{"key": "value2"}, scope3.All())
	scope3.Assign("key", "value3")
	assert.Equal(t, "value3", scope3.Get("key"))
	assert.Equal(t, "value3", scope2.Get("key"))
	assert.Equal(t, map[string]interface{}{"key": "value3"}, scope3.All())
}
