// digoxin — anonymous, attested usage counting and crash reports for macOS apps.
//
// Apps link the Digoxin Swift package, which registers a Secure Enclave
// key per install against Apple's App Attest and DeviceCheck evidence and
// sends signed heartbeats and scrubbed crash reports, at the tier the
// person chose. This service takes them for every app in the apps file.
//
// Usage:
//
//	digoxin [serve] -config /etc/digoxin/apps.json -addr 127.0.0.1:9130 -admin-addr 127.0.0.1:9131 -data /var/lib/digoxin
//	digoxin backup -data /var/lib/digoxin -dir /var/backups/digoxin
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/kageroumado/digoxin/server/internal/service"
)

const (
	defaultData       = "/var/lib/digoxin"
	databaseName      = "digoxin.db"
	backupPrefix      = "digoxin-"
	retentionInterval = 6 * time.Hour
	maxHeaderBytes    = 16 << 10
)

func main() {
	args := os.Args[1:]
	command := "serve"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		command, args = args[0], args[1:]
	}
	var err error
	switch command {
	case "serve":
		err = serve(args)
	case "backup":
		err = backup(args)
	default:
		err = fmt.Errorf("unknown command %q (serve, backup)", command)
	}
	if err != nil {
		log.Fatalf("digoxin: %v", err)
	}
}

func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := flags.String("config", "/etc/digoxin/apps.json", "the apps file")
	addr := flags.String("addr", "127.0.0.1:9130", "public listen address (Caddy proxies to it)")
	adminAddr := flags.String("admin-addr", "127.0.0.1:9131", "admin listen address, loopback only; empty disables it")
	data := flags.String("data", defaultData, "directory holding the database and crash report files")
	_ = flags.Parse(args)

	if *adminAddr != "" {
		if err := service.LoopbackOnly(*adminAddr); err != nil {
			return err
		}
	}
	config, err := service.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if host, _, err := net.SplitHostPort(*addr); err == nil && config.ClientIPHeader == "" {
		if ip := net.ParseIP(host); host == "localhost" || ip != nil && ip.IsLoopback() {
			log.Printf("digoxin: WARNING: listening on loopback with no client_ip_header: behind a proxy every client shares the proxy's address and its rate limits")
		}
	}
	if err := os.MkdirAll(*data, 0o750); err != nil {
		return err
	}
	store, err := service.OpenStore(filepath.Join(*data, databaseName))
	if err != nil {
		return err
	}
	defer store.Close()
	svc, err := service.New(store, config, filepath.Join(*data, "crashes"))
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go svc.Retain(ctx, retentionInterval)

	if *adminAddr != "" {
		adminServer := newServer(*adminAddr, svc.AdminRoutes())
		go func() {
			log.Printf("digoxin: admin on %s", *adminAddr)
			if err := adminServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("digoxin: admin listener: %v", err)
			}
		}()
		defer adminServer.Close()
	}

	server := newServer(*addr, svc.Routes())
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("digoxin: listening on %s for %s, data in %s", *addr, strings.Join(config.Slugs(), ", "), *data)
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func newServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr: addr, Handler: handler, MaxHeaderBytes: maxHeaderBytes,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second,
	}
}

// backup writes a consistent copy of the live database with VACUUM INTO,
// then keeps the newest -keep copies. Crash report files are plain files
// under <data>/crashes and are backed up as such.
func backup(args []string) error {
	flags := flag.NewFlagSet("backup", flag.ExitOnError)
	data := flags.String("data", defaultData, "directory holding the database")
	dir := flags.String("dir", "/var/backups/digoxin", "where the dated copies go")
	keep := flags.Int("keep", 30, "how many daily copies to keep")
	_ = flags.Parse(args)

	store, err := service.OpenStore(filepath.Join(*data, databaseName))
	if err != nil {
		return err
	}
	defer store.Close()
	if err := os.MkdirAll(*dir, 0o750); err != nil {
		return err
	}
	// Every name carries the time, so names sort in the order they were made.
	target := filepath.Join(*dir, backupPrefix+time.Now().UTC().Format("20060102-150405")+".db")
	if err := store.Backup(context.Background(), target); err != nil {
		return err
	}
	fmt.Println(target)
	return prune(*dir, *keep)
}

// prune removes the oldest dated copies beyond keep.
func prune(dir string, keep int) error {
	matches, err := filepath.Glob(filepath.Join(dir, backupPrefix+"*.db"))
	if err != nil {
		return err
	}
	sort.Strings(matches)
	for len(matches) > keep {
		if err := os.Remove(matches[0]); err != nil {
			return err
		}
		matches = matches[1:]
	}
	return nil
}
