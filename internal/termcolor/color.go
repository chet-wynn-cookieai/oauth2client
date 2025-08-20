package termcolor

import "fmt"

func Green(s any) string {
	return fmt.Sprintf("\033[32m%v\033[0m", s)
}

func Yellow(s any) string {
	return fmt.Sprintf("\033[33m%v\033[0m", s)
}

func Cyan(s any) string {
	return fmt.Sprintf("\033[36m%v\033[0m", s)
}

func Blue(s any) string {
	return fmt.Sprintf("\033[34m%v\033[0m", s)
}

func Red(s any) string {
	return fmt.Sprintf("\033[31m%v\033[0m", s)
}

func Magenta(s any) string {
	return fmt.Sprintf("\033[35m%v\033[0m", s)
}
