package nginx_util

import (
	"os/exec"
)

func Reload() error {
	cmd := exec.Command("nginx", "-s", "reload")
	cmd.Dir = "/"
	return cmd.Run()
}
