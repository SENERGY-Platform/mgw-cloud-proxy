package pid_file

import (
	"os"
	"strconv"
)

func Write(p string) error {
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(strconv.FormatInt(int64(os.Getpid()), 10))
	if err != nil {
		return err
	}
	return nil
}

func Remove(p string) error {
	return os.Remove(p)
}
