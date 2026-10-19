package firewall

import "os"

func lookupEnv(key string) (string, bool) {
	return os.LookupEnv(key)
}

func isTruthy(v string) bool {
	switch v {
	case "1", "true", "TRUE", "True", "yes", "on":
		return true
	}
	return false
}
