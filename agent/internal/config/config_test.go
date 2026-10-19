package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCommandsAreAllowedUnlessTheHostRefusesThem(t *testing.T) {
	for doc, want := range map[string]bool{
		"server: {url: x}":                         false, // key absent: the server's approval gates them
		"live_response: {}":                        false,
		"live_response: {disable_commands: true}":  true,
		"live_response: {disable_commands: false}": false,
	} {
		var c Config
		if err := yaml.Unmarshal([]byte(doc), &c); err != nil {
			t.Fatal(err)
		}
		if got := c.LiveResponse.CommandsDisabled(); got != want {
			t.Errorf("%q: CommandsDisabled() = %v, want %v", doc, got, want)
		}
	}
}
