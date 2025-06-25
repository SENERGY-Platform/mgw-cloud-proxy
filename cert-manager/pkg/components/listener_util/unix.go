package listener_util

import (
	"io/fs"
	"net"
	"os"
)

func NewUnix(path string, uid int, gid int, mode fs.FileMode) (listener *net.UnixListener, err error) {
	if err = clean(path); err != nil {
		return
	}
	if listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"}); err != nil {
		return
	}
	defer func() {
		if err != nil {
			_ = listener.Close()
			_ = clean(path)
		}
	}()
	if os.Getuid() == 0 {
		if err = os.Chown(path, uid, gid); err != nil {
			return
		}
	}
	if err = os.Chmod(path, mode); err != nil {
		return
	}
	return
}

func clean(path string) (err error) {
	if _, err = os.Stat(path); err == nil {
		return os.Remove(path)
	} else if os.IsNotExist(err) {
		err = nil
	}
	return
}
