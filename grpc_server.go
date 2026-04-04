package main

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func NewGRPCServerWithOptions(maxRecvMsgSize, maxSendMsgSize int, enableReflection bool, interceptors ...grpc.UnaryServerInterceptor) *grpc.Server {
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(maxRecvMsgSize),
		grpc.MaxSendMsgSize(maxSendMsgSize),
		grpc.ChainUnaryInterceptor(interceptors...),
	}

	return grpc.NewServer(opts...)
}

func grpcLoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()

		resp, err := handler(ctx, req)

		latency := time.Since(start)
		code := status.Code(err)

		clientIP := "unknown"
		if p, ok := peer.FromContext(ctx); ok {
			clientIP = p.Addr.String()
		}

		if err != nil {
			slog.Error("gRPC request",
				"method", info.FullMethod,
				"code", code.String(),
				"latency", latency,
				"client_ip", clientIP,
				"err", err,
			)
		} else {
			slog.Info("gRPC request",
				"method", info.FullMethod,
				"code", code.String(),
				"latency", latency,
				"client_ip", clientIP,
			)
		}

		RecordGRPCRequest(info.FullMethod, code.String())

		return resp, err
	}
}

func grpcTimeoutInterceptor(defaultTimeout time.Duration) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		_, ok := ctx.Deadline()
		if !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
			defer cancel()
		}
		return handler(ctx, req)
	}
}

func grpcRecoveryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("gRPC panic recovered", "method", info.FullMethod, "panic", r)
				err = status.Errorf(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}
