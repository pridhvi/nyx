package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

type Options struct {
	Level  string
	Format string
	Output io.Writer
}

func ConfigureFromEnv() error {
	return Configure(Options{
		Level:  os.Getenv("NOX_LOG_LEVEL"),
		Format: os.Getenv("NOX_LOG_FORMAT"),
	})
}

func Configure(options Options) error {
	level, err := ParseLevel(options.Level)
	if err != nil {
		return err
	}
	format, err := ParseFormat(options.Format)
	if err != nil {
		return err
	}
	output := options.Output
	if output == nil {
		output = os.Stderr
	}
	handlerOptions := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(output, handlerOptions)
	} else {
		handler = slog.NewTextHandler(output, handlerOptions)
	}
	slog.SetDefault(slog.New(handler))
	return nil
}

func ParseLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid log level %q", value)
	}
}

func ParseFormat(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "text":
		return "text", nil
	case "json":
		return "json", nil
	default:
		return "", fmt.Errorf("invalid log format %q", value)
	}
}
