package appctx

import (
	"context"
	"time"

	"github.com/ahmedbaig/dashboard-auth/internal/config"
	"github.com/ahmedbaig/go-backend-db"
	"github.com/ahmedbaig/go-backend-db/dbgrpc"
	"github.com/ahmedbaig/go-backend-proto/grpcx"
	"google.golang.org/grpc"
)

func connectDB(c config.Config) (*db.Client, *grpc.ClientConn, error) {
	h := c.App.DBHandler
	var opts []db.ClientOption
	if h.Instance != "" {
		opts = append(opts, db.WithInstance(h.Instance))
	}
	return dbgrpc.Dial(c.DBHandlerAddr(), grpcx.ClientOptions{
		ServiceToken: c.Shared.ServiceToken,
		Extra:        []grpc.DialOption{grpc.WithUnaryInterceptor(timeout(h.Timeout.Std()))},
	}, opts...)
}

func timeout(d time.Duration) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if _, ok := ctx.Deadline(); !ok && d > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, d)
			defer cancel()
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
