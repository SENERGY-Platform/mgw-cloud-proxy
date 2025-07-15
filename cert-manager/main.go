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
	client_ca "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/clients/ca"
	client_cloud "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/clients/cloud"
	handler_cert "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/handler/cert"
	handler_storage "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/handler/storage"
	helper_http "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/helper/http"
	helper_jwt "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/helper/jwt"
	helper_listener "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/helper/listener"
	helper_nginx "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/helper/nginx"
	helper_os_signal "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/helper/os_signal"
	helper_pid_file "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/helper/pid_file"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/config"
	models_api "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/api"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/slog_attr"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/service"
	dep_adv_client "github.com/SENERGY-Platform/mgw-module-manager/clients/dep-adv-client"
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

	if config.Deploy {
		certHdl := handler_cert.New(nil, cfg.CertHdl)
		err = certHdl.Deploy(context.Background())
		if err != nil {
			fmt.Println(err)
			ec = 1
			return
		}
		return
	}

	err = helper_pid_file.Write(cfg.PidFilePath)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		ec = 1
		return
	}
	defer helper_pid_file.Remove(cfg.PidFilePath)

	logger := struct_logger.New(cfg.Logger, os.Stderr, "", srvInfoHdl.Name())

	logger.Info("starting service", slog_attr.VersionKey, srvInfoHdl.Version(), slog_attr.ConfigValuesKey, sb_config_hdl.StructToMap(cfg, true))

	caClt, err := client_ca.New(cfg.Cloud.TokenBaseUrl, cfg.Cloud.CertBaseUrl)
	if err != nil {
		logger.Error("creating certificate authority client failed", attributes.ErrorKey, err)
		ec = 1
		return
	}

	handler_cert.InitLogger(logger)
	certHdl := handler_cert.New(caClt, cfg.CertHdl)
	if err = certHdl.Init(); err != nil {
		logger.Error("initializing certificate handler failed", attributes.ErrorKey, err)
		ec = 1
		return
	}

	storageHdl := handler_storage.New(cfg.StoragePath)
	if err = storageHdl.Init(); err != nil {
		logger.Error("initializing storage handler failed", attributes.ErrorKey, err)
		ec = 1
		return
	}

	service.InitLogger(logger)
	srv := service.New(
		certHdl,
		storageHdl,
		dep_adv_client.New(helper_http.NewClient(cfg.DepAdv.HttpTimeout), cfg.DepAdv.ModuleManagerBaseUrl),
		client_cloud.New(helper_http.NewClient(cfg.Cloud.HttpTimeout), cfg.Cloud.CertBaseUrl, cfg.Cloud.TokenBaseUrl),
		helper_jwt.GetSubject,
		helper_nginx.Reload,
		srvInfoHdl,
		cfg.Service,
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
	serverListener, err := helper_listener.NewUnix(cfg.Socket)
	if err != nil {
		logger.Error("creating server listener failed", attributes.ErrorKey, err)
		ec = 1
		return
	}

	ctx, cf := context.WithCancel(context.Background())

	go func() {
		helper_os_signal.Wait(ctx, logger, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		cf()
	}()

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.PeriodicCertificateRenewal(ctx, time.Hour); err != nil {
			logger.Error("periodic certificate renewal failed", attributes.ErrorKey, err)
			ec = 1
		}
		cf()
	}()

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
