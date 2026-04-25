package env

import (
	"os"
	"sync"
)

var (
	isProduction bool
	once         sync.Once
)

func initEnv() {
	isProduction = os.Getenv("ENV") == "production"
}

func Init() {
	once.Do(initEnv)
}

func IsProduction() bool {
	once.Do(initEnv)
	return isProduction
}

func ShouldLog() bool {
	return !IsProduction()
}
