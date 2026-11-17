package grpc

import (
	"context"
	"log/slog"
	"net"

	"github.com/ahmedbaig/dashboard-auth/internal/http/services"
	authv1 "github.com/ahmedbaig/dashboard-auth/proto/gen/go/dashboard/auth/v1"
	"github.com/ahmedbaig/go-backend-proto/grpcx"
	"github.com/ahmedbaig/go-backend-types"
	"google.golang.org/grpc"
)

type Auth struct {
	authv1.UnimplementedAuthServiceServer
	auth     *services.AuthService
	sessions *services.SessionsService
	users    *services.UsersService
}

type Server struct {
	srv  *grpcx.Server
	addr string
	log  *slog.Logger
	lis  net.Listener
}

type Principal struct {
	User types.User
	SID  string
}

type principalKey struct{}

type stream struct {
	grpc.ServerStream
	ctx context.Context
}
