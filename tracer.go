package main

import (
	"context"
	"log/slog"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

func InitTracer(cfg *Config) func() {
	if !cfg.OTel.Enabled {
		slog.Info("OpenTelemetry disabled")
		return func() {}
	}

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	var exporter trace.SpanExporter
	var err error

	if cfg.OTel.Endpoint != "" {
		slog.Info("OpenTelemetry initializing", "mode", "otlp", "endpoint", cfg.OTel.Endpoint)
		exporter, err = otlptracegrpc.New(context.Background(),
			otlptracegrpc.WithEndpoint(cfg.OTel.Endpoint),
			otlptracegrpc.WithInsecure(),
		)
	} else {
		slog.Info("OpenTelemetry initializing", "mode", "stdout")
		exporter, err = stdouttrace.New(
			stdouttrace.WithWriter(os.Stdout),
			stdouttrace.WithPrettyPrint(),
		)
	}

	if err != nil {
		slog.Warn("OpenTelemetry init failed, using no-op tracer", "err", err, "endpoint", cfg.OTel.Endpoint)
		return func() {}
	}

	tp := trace.NewTracerProvider(
		trace.WithBatcher(exporter),
		trace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("zeek_runner"),
			semconv.ServiceVersion("1.0.0"),
		)),
	)

	otel.SetTracerProvider(tp)

	if cfg.OTel.Endpoint != "" {
		slog.Info("OpenTelemetry initialized", "mode", "otlp", "endpoint", cfg.OTel.Endpoint)
	} else {
		slog.Info("OpenTelemetry initialized", "mode", "stdout")
	}

	return func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			slog.Error("OpenTelemetry shutdown error", "err", err)
		}
	}
}
