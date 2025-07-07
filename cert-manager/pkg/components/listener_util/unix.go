package listener_util

import (
	"net"
	"os"
)

func NewUnix(config Config) (listener *net.UnixListener, err error) {
	if err = clean(config.Path); err != nil {
		return
	}
	if listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: config.Path, Net: "unix"}); err != nil {
		return
	}
	defer func() {
		if err != nil {
			_ = listener.Close()
			_ = clean(config.Path)
		}
	}()
	if os.Getuid() == 0 {
		if err = os.Chown(config.Path, config.UserID, config.GroupID); err != nil {
			return
		}
	}
	if err = os.Chmod(config.Path, config.FileMode); err != nil {
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
