package file

import (
	"io"
	"os"
)

func BackupFile(pth string, perm os.FileMode) (string, error) {
	_, err := os.Stat(pth)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	bkPth := pth + ".bk"
	if err = Copy(pth, bkPth, perm); err != nil {
		os.Remove(bkPth)
		return "", err
	}
	return bkPth, nil
}

func Copy(srcPath, targetPath string, perm os.FileMode) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	targetFile, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer targetFile.Close()
	_, err = io.Copy(targetFile, srcFile)
	if err != nil {
		return err
	}
	return nil
}
