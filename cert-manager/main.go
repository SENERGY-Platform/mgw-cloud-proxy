package main

import (
	"context"
	"errors"
	"fmt"
	sb_config_hdl "github.com/SENERGY-Platform/go-service-base/config-hdl"
	"github.com/SENERGY-Platform/go-service-base/srv-info-hdl"
	struct_logger "github.com/SENERGY-Platform/go-service-base/struct-logger"
	"github.com/SENERGY-Platform/go-service-base/struct-logger/attributes"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/api"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/cert_hdl"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/cert_hdl/ca_clt"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/cloud_clt"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/jwt_util"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/listener_util"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/nginx_util"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/os_signal_util"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/pid_file_util"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/storage_hdl"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/config"
	models_api "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/api"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/slog_attr"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/service"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"
)

var version string

func main() {
	ec := 0
	defer func() {
		os.Exit(ec)
	}()

	srvInfoHdl := srv_info_hdl.New("cert-manager", version)

	config.ParseFlags()

	cfg, err := config.New(config.ConfPath)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		ec = 1
		return
	}

	err = pid_file_util.WritePidFile(cfg.PidFilePath)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		ec = 1
		return
	}
	defer pid_file_util.RemovePidFile(cfg.PidFilePath)

	logger := struct_logger.New(cfg.Logger, os.Stderr, "", srvInfoHdl.Name())

	logger.Info("starting service", slog_attr.VersionKey, srvInfoHdl.Version(), slog_attr.ConfigValuesKey, sb_config_hdl.StructToMap(cfg, true))

	caClt, err := ca_clt.New(cfg.Cloud.TokenBaseUrl, cfg.Cloud.CertBaseUrl)
	if err != nil {
		logger.Error("creating certificate authority client failed", attributes.ErrorKey, err)
		ec = 1
		return
	}

	cert_hdl.InitLogger(logger)
	certHdl := cert_hdl.New(caClt, cfg.CertHdl)
	if err = certHdl.Init(); err != nil {
		logger.Error("initializing certificate handler failed", attributes.ErrorKey, err)
		ec = 1
		return
	}

	storageHdl := storage_hdl.New(cfg.StoragePath)
	if err = storageHdl.Init(); err != nil {
		logger.Error("initializing storage handler failed", attributes.ErrorKey, err)
		ec = 1
		return
	}

	cloudHttpClient := &http.Client{
		Timeout: cfg.Cloud.HttpTimeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	service.InitLogger(logger)
	srv := service.New(
		certHdl,
		storageHdl,
		cloud_clt.New(cloudHttpClient, cfg.Cloud.CertBaseUrl, cfg.Cloud.TokenBaseUrl),
		jwt_util.GetSubject,
		nginx_util.Reload,
		srvInfoHdl,
	)

	httpHandler, err := api.New(
		srv,
		map[string]string{
			models_api.HeaderApiVer:  srvInfoHdl.Version(),
			models_api.HeaderSrvName: srvInfoHdl.Name(),
		},
		logger,
		cfg.HttpAccessLog,
	)
	if err != nil {
		logger.Error("creating http engine failed", attributes.ErrorKey, err)
		ec = 1
		return
	}

	httpServer := &http.Server{Handler: httpHandler}
	serverListener, err := listener_util.NewUnix(cfg.Socket)
	if err != nil {
		logger.Error("creating server listener failed", attributes.ErrorKey, err)
		ec = 1
		return
	}

	ctx, cf := context.WithCancel(context.Background())

	go func() {
		os_signal_util.Wait(ctx, logger, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		cf()
	}()

	wg := &sync.WaitGroup{}

	go func() {
		logger.Info("starting http server")
		if err := httpServer.Serve(serverListener); !errors.Is(err, http.ErrServerClosed) {
			logger.Error("starting server failed", attributes.ErrorKey, err)
			ec = 1
		}
		cf()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		logger.Info("stopping http server")
		ctxWt, cf2 := context.WithTimeout(context.Background(), time.Second*5)
		defer cf2()
		if err := httpServer.Shutdown(ctxWt); err != nil {
			logger.Error("stopping server failed", attributes.ErrorKey, err)
			ec = 1
		} else {
			logger.Info("http server stopped")
		}
	}()

	wg.Wait()
}
