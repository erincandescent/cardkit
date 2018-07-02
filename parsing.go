package dshl

import (
	"github.com/mattn/go-shellwords"
)

func SplitWords(line string) ([]string, error) {
	return shellwords.Parse(line)
}
