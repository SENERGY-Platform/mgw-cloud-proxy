package pid_file_util

import (
	"os"
	"strconv"
)

func WritePidFile(p string) error {
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

func RemovePidFile(p string) error {
	return os.Remove(p)
}
