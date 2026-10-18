package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/fu5ha/vaultbroker/internal/api"
	"github.com/fu5ha/vaultbroker/internal/broker"
	"github.com/fu5ha/vaultbroker/internal/bw"
	"github.com/fu5ha/vaultbroker/internal/helper"
	"github.com/fu5ha/vaultbroker/internal/web"
)

func main() {
	configPath := flag.String("config", "/etc/vaultbroker/config.json", "path to config.json")
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("vaultbroker: ")

	cfg, err := broker.LoadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	audit, err := broker.OpenAuditLog(cfg.AuditPath)
	if err != nil {
		log.Fatal(err)
	}
	defer audit.Close()

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	bwClient := bw.New(cfg.BWPath, cfg.VaultwardenURL, home)
	b := broker.New(cfg, audit, bwClient, helper.New(cfg.HelperURL, cfg.HelperToken))
	if err := b.LoadScope(); err != nil {
		log.Fatal(err)
	}

	socket, err := api.Listen(b, cfg.SocketPath)
	if err != nil {
		log.Fatal(err)
	}
	defer socket.Close()
	defer os.Remove(cfg.SocketPath)
	go func() {
		if err := socket.Serve(); err != nil {
			log.Printf("socket server: %v", err)
		}
	}()

	pages, err := web.New(b)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: cfg.WebAddr, Handler: pages.Handler()}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("web server: %v", err)
		}
	}()

	if !b.Status().Configured {
		log.Print("vault scope not pinned yet; it pins itself at first unlock if unambiguous")
	}
	log.Printf("listening: socket %s, web %s, vault locked", cfg.SocketPath, cfg.WebAddr)
	audit.Write(broker.AuditEvent{Event: "broker.started"})

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	b.Lock(context.Background())
	_ = server.Close()
}
