package logger

import (
	"log"
	"os"
)

var (
	debugEnabled bool
	infoLogger   *log.Logger
	debugLogger  *log.Logger
	errorLogger  *log.Logger
)

func init() {
	infoLogger = log.New(os.Stderr, "[INFO] ", log.Ltime|log.Lshortfile)
	debugLogger = log.New(os.Stderr, "[DEBUG] ", log.Ltime|log.Lshortfile)
	errorLogger = log.New(os.Stderr, "[ERROR] ", log.Ltime|log.Lshortfile)
}

func SetDebug(enabled bool) {
	debugEnabled = enabled
}

func IsDebugEnabled() bool {
	return debugEnabled
}

func Info(format string, args ...any) {
	infoLogger.Printf(format, args...)
}

func Debug(format string, args ...any) {
	if debugEnabled {
		debugLogger.Printf(format, args...)
	}
}

func Error(format string, args ...any) {
	errorLogger.Printf(format, args...)
}
