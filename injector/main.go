package main

import (
	"flag"
	"log/slog"
	"mem/proc"
	"os"
	"path/filepath"
	"time"

	"github.com/lmittmann/tint"
)

func setupLogging(debug bool) {
	logLevel := slog.LevelInfo
	if debug {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(
		tint.NewTextHandler(os.Stderr, &tint.Options{
			Level:      logLevel,
			TimeFormat: time.Kitchen,
		}))
	slog.SetDefault(logger)
}

func main() {
	debug := flag.Bool("d", false, "enable debug logging")
	procName := flag.String("proc", "", "process name")
	dllPath := flag.String("dll", "", "path to the dll to inject")
	flag.Parse()

	setupLogging(*debug)

	if *procName == "" || *dllPath == "" {
		flag.Usage()
		os.Exit(2)
	}

	absDLLPath, err := filepath.Abs(*dllPath)
	if err != nil {
		slog.Error("error resolving dll path", tint.Err(err))
		os.Exit(1)
	}
	if _, err := os.Stat(absDLLPath); err != nil {
		slog.Error("dll not found", tint.Err(err))
		os.Exit(1)
	}

	p, err := proc.OpenProc(*procName)
	if err != nil {
		slog.Error("error opening process", tint.Err(err))
		os.Exit(1)
	}
	slog.Info("opened process", "name", *procName)
	defer func() {
		slog.Info("closing process")
		if err := p.Close(); err != nil {
			slog.Error("error closing process", tint.Err(err))
		}
	}()

	err = p.InjectDLL(absDLLPath)
	if err != nil {
		slog.Error("error injecting dll", tint.Err(err))
		os.Exit(1)
	}

	slog.Info("injected dll successfully")
}
