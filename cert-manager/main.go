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
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/listener_util"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/os_signal_util"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/pid_file_util"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/config"
	models_api "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/api"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/slog_attr"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/service"
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

	cert_hdl.InitLogger(logger)
	certHdl := cert_hdl.New(nil, nil, cert_hdl.Config{})

	srv := service.New(certHdl, srvInfoHdl)

	httpHandler, err := api.New(srv, map[string]string{
		models_api.HeaderApiVer:  srvInfoHdl.Version(),
		models_api.HeaderSrvName: srvInfoHdl.Name(),
	}, logger, cfg.HttpAccessLog)
	if err != nil {
		logger.Error("creating http engine failed", attributes.ErrorKey, err)
		ec = 1
		return
	}

	httpServer := &http.Server{Handler: httpHandler}
	serverListener, err := listener_util.NewUnix(cfg.Socket.Path, os.Getuid(), cfg.Socket.GroupID, cfg.Socket.FileMode)
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

	//if err = swaggerStgHdl.Init(ctx); err != nil {
	//	util.Logger.Error("initializing swagger storage handler failed", attributes.ErrorKey, err)
	//	ec = 1
	//	return
	//}

	wg := &sync.WaitGroup{}

	//wg.Add(1)
	//go func() {
	//	defer wg.Done()
	//	if err := swaggerSrv.SwaggerPeriodicProcurement(ctx, cfg.Procurement.Interval, cfg.Procurement.InitialDelay); err != nil {
	//		util.Logger.Error("periodic procurement failed", attributes.ErrorKey, err)
	//		ec = 1
	//	}
	//	cf()
	//}()

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

//func main() {
//	pid := os.Getpid()
//	fmt.Println("start", pid)
//	err := writePidFile(pid)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer os.Remove("/var/run/cert_manager.pid")
//
//	ctx, cf := context.WithCancel(context.Background())
//
//	go func() {
//		WaitForSignal(ctx, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGHUP)
//		cf()
//	}()
//
//	err = WriteFile(ctx)
//	if err != nil {
//		fmt.Println(err)
//	}
//	fmt.Println("done")
//}
//
//func writePidFile(pid int) error {
//	f, err := os.Create("/var/run/cert_manager.pid")
//	if err != nil {
//		return err
//	}
//	defer f.Close()
//	_, err = f.WriteString(strconv.FormatInt(int64(pid), 10))
//	if err != nil {
//		return err
//	}
//	return nil
//}
//
//func WriteFile(ctx context.Context) error {
//	f, err := os.Create("test")
//	if err != nil {
//		return err
//	}
//	defer f.Close()
//	var c int64
//	for {
//		select {
//		case <-ctx.Done():
//			return ctx.Err()
//		default:
//			//if c == 10 {
//			//	fmt.Println("ohhh noooooo")
//			//	return errors.New("ohh noooo")
//			//}
//			_, err = f.WriteString(fmt.Sprintf("%d\n", c))
//			if err != nil {
//				return err
//			}
//			if err = f.Sync(); err != nil {
//				return err
//			}
//			c++
//			time.Sleep(time.Second)
//		}
//	}
//}
//
//func WaitForSignal(ctx context.Context, signals ...os.Signal) {
//	ch := make(chan os.Signal, 1)
//	for _, sig := range signals {
//		signal.Notify(ch, sig)
//	}
//	select {
//	case sig := <-ch:
//		fmt.Println("caught os signal", sig.String())
//		break
//	case <-ctx.Done():
//		break
//	}
//	signal.Stop(ch)
//}
