package main

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	tasksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "zeek_tasks_total",
			Help: "Total number of zeek tasks processed",
		},
		[]string{"status"},
	)

	taskDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "zeek_task_duration_seconds",
			Help:    "Duration of zeek task execution in seconds",
			Buckets: prometheus.ExponentialBuckets(1, 2, 10),
		},
	)

	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	grpcRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "grpc_requests_total",
			Help: "Total number of gRPC requests",
		},
		[]string{"method", "code"},
	)
)

func init() {
	prometheus.MustRegister(tasksTotal)
	prometheus.MustRegister(taskDuration)
	prometheus.MustRegister(requestsTotal)
	prometheus.MustRegister(grpcRequestsTotal)
}

func RecordTask(status string, durationSeconds float64) {
	tasksTotal.WithLabelValues(status).Inc()
	taskDuration.Observe(durationSeconds)
}

func RecordRequest(method, path, status string) {
	requestsTotal.WithLabelValues(method, path, status).Inc()
}

func RecordGRPCRequest(method, code string) {
	grpcRequestsTotal.WithLabelValues(method, code).Inc()
}

func prometheusHandler() gin.HandlerFunc {
	h := promhttp.Handler()
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

type MetricsCollector struct {
	app *App
}

func NewMetricsCollector(app *App) *MetricsCollector {
	return &MetricsCollector{app: app}
}

func (m *MetricsCollector) Register() {
	prometheus.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "zeek_pool_running",
			Help: "Number of currently running tasks in the pool",
		},
		func() float64 {
			if m.app.TaskPool != nil {
				return float64(m.app.TaskPool.Running())
			}
			return 0
		},
	))

	prometheus.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "zeek_pool_capacity",
			Help: "Maximum capacity of the task pool",
		},
		func() float64 {
			cfg := m.app.ConfigManager.Get()
			return float64(cfg.Pool.Size)
		},
	))

	prometheus.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "zeek_kafka_ready",
			Help: "Whether kafka is ready (1) or not (0)",
		},
		func() float64 {
			if m.app.IsKafkaReady() {
				return 1
			}
			return 0
		},
	))
}
