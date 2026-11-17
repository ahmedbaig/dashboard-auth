package session

import (
	"context"
	"errors"
	"time"

	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	"github.com/redis/go-redis/v9"
)

func NewLockout(rdb redis.UniversalClient, prefix string, maxFailures int, window time.Duration) *Lockout {
	return &Lockout{rdb: rdb, prefix: prefix, max: int64(maxFailures), window: window}
}

func (l *Lockout) key(email string) string { return l.prefix + constants.KeyLoginFail + email }

func (l *Lockout) Locked(ctx context.Context, email string) (time.Duration, error) {
	n, err := l.rdb.Get(ctx, l.key(email)).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil || n < l.max {
		return 0, err
	}
	return l.rdb.PTTL(ctx, l.key(email)).Result()
}

func (l *Lockout) Fail(ctx context.Context, email string) error {
	_, err := l.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.Incr(ctx, l.key(email))
		p.Expire(ctx, l.key(email), l.window)
		return nil
	})
	return err
}

func (l *Lockout) Clear(ctx context.Context, email string) error {
	return l.rdb.Del(ctx, l.key(email)).Err()
}
