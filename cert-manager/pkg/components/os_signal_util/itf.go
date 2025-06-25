package os_signal_util

type logger interface {
	Warn(msg string, args ...any)
}
