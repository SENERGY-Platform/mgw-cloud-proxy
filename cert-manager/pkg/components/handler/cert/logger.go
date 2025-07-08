package cert

import (
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/slog_attr"
	"log/slog"
)

var logger *slog.Logger

func InitLogger(sl *slog.Logger) {
	logger = sl.With(slog_attr.ComponentKey, "handler-cert")
}
