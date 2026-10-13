package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/userreksai/anquan-server-master/internal/server"
)

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("anquan-master stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "reset-admin" {
		return reset(args[1:])
	}
	if len(args) > 0 && args[0] == "save-agent-template" {
		return saveAgentTemplate(args[1:])
	}
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	flags := flag.NewFlagSet("anquan-master", flag.ContinueOnError)
	dataDir := flags.String("data-dir", env("ANQUAN_DATA_DIR", "/data/anquan"), "SQLite data directory")
	httpAddr := flags.String("http", env("ANQUAN_HTTP_ADDR", env("HTTP_ADDR", ":10110")), "HTTP listen address")
	udpAddr := flags.String("udp", env("ANQUAN_UDP_ADDR", env("UDP_ADDR", ":55555")), "UDP listen address")
	tcpAddr := flags.String("tcp", env("ANQUAN_TCP_ADDR", ":55556"), "agent configuration TCP listen address")
	secureDefault, err := strconv.ParseBool(env("ANQUAN_SECURE_COOKIE", "false"))
	if err != nil {
		return fmt.Errorf("ANQUAN_SECURE_COOKIE: %w", err)
	}
	secureCookie := flags.Bool("secure-cookie", secureDefault, "require HTTPS for session cookies")
	publicOrigin := flags.String("public-origin", env("ANQUAN_PUBLIC_ORIGIN", ""), "browser-facing HTTP(S) origin for write-request validation")
	if err = flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	// Validate deployment settings before creating the database or listeners.
	srv := server.New(nil, *secureCookie, slog.Default())
	if err = srv.SetPublicOrigin(*publicOrigin); err != nil {
		return fmt.Errorf("--public-origin/ANQUAN_PUBLIC_ORIGIN: %w", err)
	}
	store, err := server.Open(*dataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	srv.Store = store
	udp, err := net.ResolveUDPAddr("udp", *udpAddr)
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udp)
	if err != nil {
		return err
	}
	defer udpConn.Close()
	listener, err := net.Listen("tcp", *httpAddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	tcpListener, err := net.Listen("tcp", *tcpAddr)
	if err != nil {
		return fmt.Errorf("listen agent configuration TCP: %w", err)
	}
	defer tcpListener.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	httpServer := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	errorsCh := make(chan error, 3)
	tcpDone := make(chan struct{})
	go func() { defer close(tcpDone); errorsCh <- srv.ServeAgentTCP(ctx, tcpListener) }()
	go func() { errorsCh <- store.ServeUDP(ctx, udpConn, slog.Default()) }()
	go func() { errorsCh <- httpServer.Serve(listener) }()
	notifyDone := make(chan struct{})
	go func() { defer close(notifyDone); srv.RunNotifier(ctx) }()
	offlineDone := make(chan struct{})
	go func() { defer close(offlineDone); srv.RunOfflineMonitor(ctx) }()
	slog.Info("安全中心主控已启动", "http", listener.Addr().String(), "udp", udpConn.LocalAddr().String(), "tcp", tcpListener.Addr().String(), "database", filepath.Join(*dataDir, "anquan.db"))
	select {
	case <-ctx.Done():
	case err = <-errorsCh:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	cancel()
	_ = udpConn.Close()
	shutdown, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	if e := httpServer.Shutdown(shutdown); err == nil {
		err = e
	}
	<-notifyDone
	<-offlineDone
	<-tcpDone
	return err
}

func reset(args []string) error {
	flags := flag.NewFlagSet("reset-admin", flag.ContinueOnError)
	dataDir := flags.String("data-dir", env("ANQUAN_DATA_DIR", "/data/anquan"), "existing SQLite data directory")
	passwordStdin := flags.Bool("password-stdin", false, "read the new password from stdin")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	if !*passwordStdin {
		return errors.New("必须通过 --password-stdin 输入新密码")
	}
	info, err := os.Stat(filepath.Join(*dataDir, "anquan.db"))
	if err != nil || info.IsDir() {
		return errors.New("指定目录中不存在 anquan.db；请确认 --data-dir")
	}
	password, err := io.ReadAll(io.LimitReader(os.Stdin, 1025))
	if err != nil {
		return err
	}
	if len(password) > 1024 {
		return errors.New("密码输入过长")
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(password), "\n"), "\r")
	if strings.ContainsAny(value, "\r\n") {
		return errors.New("密码不能包含换行")
	}
	if err = server.ValidatePassword(value); err != nil {
		return err
	}
	store, err := server.Open(*dataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	if err = store.ResetAdmin(context.Background(), value); err != nil {
		return err
	}
	fmt.Println("admin 密码已重置，所有现有登录会话已失效。")
	return nil
}

func saveAgentTemplate(args []string) error {
	flags := flag.NewFlagSet("save-agent-template", flag.ContinueOnError)
	dataDir := flags.String("data-dir", env("ANQUAN_DATA_DIR", "/data/anquan"), "existing SQLite data directory")
	yamlStdin := flags.Bool("yaml-stdin", false, "read the YAML template from stdin")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	if !*yamlStdin {
		return errors.New("必须通过 --yaml-stdin 输入 YAML 模板")
	}
	// Invalid or oversized input must never open or initialize the database.
	config, err := server.ReadAgentTemplateYAML(os.Stdin)
	if err != nil {
		return err
	}
	store, err := server.OpenExisting(*dataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	if err = store.SaveAgentConfigTemplate(context.Background(), config); err != nil {
		return err
	}
	fmt.Println("Agent 配置模板已存储到本机数据库。")
	return nil
}
