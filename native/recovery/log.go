package recovery

import "log"

func logf(format string, args ...interface{}) {
	log.Printf("[recovery] "+format, args...)
}
