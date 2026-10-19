package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCommandsAreDisabledUnlessExplicitlyAllowed(t *testing.T) {
	for doc, want := range map[string]bool{
		"server: {url: x}":                         true, // key absent: old configs stay safe
		"live_response: {}":                        true,
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
