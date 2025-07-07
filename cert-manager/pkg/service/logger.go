package service

import (
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/slog_attr"
	"log/slog"
)

var logger *slog.Logger

func InitLogger(logger *slog.Logger) {
	logger = logger.With(slog_attr.ComponentKey, "service")
}
