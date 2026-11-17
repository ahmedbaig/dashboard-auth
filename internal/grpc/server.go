package grpc

import (
	"context"
	"log/slog"
	"net"

	"github.com/ahmedbaig/dashboard-auth/internal/appctx"
	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	authv1 "github.com/ahmedbaig/dashboard-auth/proto/gen/go/dashboard/auth/v1"
	"github.com/ahmedbaig/go-backend-proto/grpcx"
)

func New(ctx *appctx.Context) *Server {
	srv := grpcx.NewServer(grpcx.ServerOptions{
		Name:          constants.Name,
		Logger:        ctx.Log,
		ServiceTokens: []string{ctx.Config.Shared.ServiceToken},
		Reflection:    ctx.Config.App.Reflection(),
		Extra:         ServerOptions(ctx.Keys.Edge),
	})
	authv1.RegisterAuthServiceServer(srv, NewAuth(ctx.Services.Auth, ctx.Services.Sessions, ctx.Services.Users))
	srv.MarkServing(authv1.AuthService_ServiceDesc.ServiceName)
	return &Server{srv: srv, addr: ctx.Config.GRPCAddr(), log: ctx.Log}
}

func (s *Server) Start() error {
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.lis = lis
	s.log.Info("grpc listening", slog.String("addr", lis.Addr().String()))
	go func() {
		if err := s.srv.Serve(lis); err != nil {
			s.log.Error("grpc stopped", slog.Any("error", err))
		}
	}()
	return nil
}

func (s *Server) Addr() string { return s.lis.Addr().String() }

func (s *Server) Shutdown(ctx context.Context) error { return s.srv.Shutdown(ctx) }
