package appctx

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/ahmedbaig/dashboard-auth/internal/config"
	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	"github.com/redis/go-redis/v9"
)

func connectRedis(c config.Config) (*redis.Client, error) {
	r := c.Shared.Redis
	o := &redis.Options{Addr: r.Addr, Username: r.Username, Password: r.Password, DB: r.DB}
	if r.TLS {
		o.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	rdb := redis.NewClient(o)
	ctx, cancel := context.WithTimeout(context.Background(), constants.RedisPingTimeout)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return rdb, fmt.Errorf("redis %s: %w", r.Addr, err)
	}
	return rdb, nil
}
