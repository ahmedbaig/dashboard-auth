package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	"github.com/ahmedbaig/go-backend-types"
	"github.com/redis/go-redis/v9"
)

func NewStore(rdb redis.UniversalClient, o Options) *Store {
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Store{rdb: rdb, prefix: o.Prefix, ttl: o.TTL, history: int64(o.HistorySize), now: o.Now}
}

func (s *Store) TTL() time.Duration { return s.ttl }

func (s *Store) keySession(sid string) string { return s.prefix + constants.KeySession + sid }
func (s *Store) keyRevoked(sid string) string { return s.prefix + constants.KeyRevoked + sid }
func (s *Store) keyUser(id int64) string {
	return s.prefix + constants.KeyUser + strconv.FormatInt(id, 10) + constants.KeyUserSession
}
func (s *Store) keyHistory(id int64) string {
	return s.prefix + constants.KeyUser + strconv.FormatInt(id, 10) + constants.KeyUserHistory
}
func (s *Store) keyGrace(sid, h string) string { return s.prefix + constants.KeyGrace + sid + ":" + h }
func (s *Store) Channel() string               { return s.prefix + constants.EventChannel }

func RandomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func NewSID() string { return RandomToken(18) }

func NewRefresh(sid string) (token, hash string) {
	secret := RandomToken(32)
	return sid + "." + secret, HashSecret(secret)
}

func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func SplitRefresh(token string) (sid, hash string, ok bool) {
	sid, secret, found := strings.Cut(token, ".")
	if !found || sid == "" || secret == "" {
		return "", "", false
	}
	return sid, HashSecret(secret), true
}

func (s *Store) Create(ctx context.Context, r Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.Set(ctx, s.keySession(r.SID), b, s.ttl)
		p.SAdd(ctx, s.keyUser(r.UserID), r.SID)
		p.Expire(ctx, s.keyUser(r.UserID), s.ttl)
		return nil
	})
	return err
}

func decode(b []byte) (Record, error) {
	var r Record
	return r, json.Unmarshal(b, &r)
}

func (s *Store) Get(ctx context.Context, sid string) (Record, bool, error) {
	b, err := s.rdb.Get(ctx, s.keySession(sid)).Bytes()
	if errors.Is(err, redis.Nil) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	r, err := decode(b)
	return r, err == nil, err
}

func (s *Store) Revoked(ctx context.Context, sid string) (string, bool, error) {
	reason, err := s.rdb.Get(ctx, s.keyRevoked(sid)).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	return reason, err == nil, err
}

func (s *Store) Rotate(ctx context.Context, sid, hash string, grace time.Duration, next func(Record) (Record, []byte, error)) (Rotation, error) {
	var (
		out Rotation
		err error
	)
	for range constants.RotateRetries {
		out, err = s.rotateOnce(ctx, sid, hash, grace, next)
		if !errors.Is(err, redis.TxFailedErr) {
			return out, err
		}
	}
	return out, err
}

func (s *Store) rotateOnce(ctx context.Context, sid, hash string, grace time.Duration, next func(Record) (Record, []byte, error)) (Rotation, error) {
	key := s.keySession(sid)
	var out Rotation
	err := s.rdb.Watch(ctx, func(tx *redis.Tx) error {
		b, err := tx.Get(ctx, key).Bytes()
		if errors.Is(err, redis.Nil) {
			return ErrSessionGone
		}
		if err != nil {
			return err
		}
		cur, err := decode(b)
		if err != nil {
			return err
		}
		switch {
		case cur.RefreshHash == hash:
		case cur.PrevHash == hash && s.now().Sub(cur.RotatedAt) <= grace:
			payload, err := tx.Get(ctx, s.keyGrace(sid, hash)).Bytes()
			if err != nil {
				out = Rotation{Record: cur}
				return ErrReuse
			}
			out = Rotation{Record: cur, Payload: payload}
			return nil
		default:
			out = Rotation{Record: cur}
			return ErrReuse
		}
		rec, payload, err := next(cur)
		if err != nil {
			out = Rotation{Record: cur}
			return err
		}
		rec.PrevHash, rec.RotatedAt = hash, s.now()
		nb, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		_, err = tx.TxPipelined(ctx, func(p redis.Pipeliner) error {
			p.Set(ctx, key, nb, s.ttl)
			p.Set(ctx, s.keyGrace(sid, hash), payload, grace)
			p.Expire(ctx, s.keyUser(rec.UserID), s.ttl)
			return nil
		})
		out = Rotation{Record: rec, Payload: payload}
		return err
	}, key)
	return out, err
}

func (s *Store) Revoke(ctx context.Context, r Record, reason string) error {
	left, err := s.rdb.PTTL(ctx, s.keySession(r.SID)).Result()
	if err != nil || left <= 0 {
		left = s.ttl
	}
	ended, err := json.Marshal(Ended{Device: r.Device, Browser: r.Browser, IP: r.IP, CreatedAt: r.CreatedAt, EndedAt: s.now(), Reason: reason})
	if err != nil {
		return err
	}
	_, err = s.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.Del(ctx, s.keySession(r.SID))
		p.SRem(ctx, s.keyUser(r.UserID), r.SID)
		p.Set(ctx, s.keyRevoked(r.SID), reason, left)
		if s.history > 0 {
			p.LPush(ctx, s.keyHistory(r.UserID), ended)
			p.LTrim(ctx, s.keyHistory(r.UserID), 0, s.history-1)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.publish(ctx, Event{Type: constants.EventRevoked, UserID: r.UserID, SIDs: []string{r.SID}, Reason: reason})
}

func (s *Store) List(ctx context.Context, userID int64) ([]Record, error) {
	sids, err := s.rdb.SMembers(ctx, s.keyUser(userID)).Result()
	if err != nil || len(sids) == 0 {
		return nil, err
	}
	keys := make([]string, len(sids))
	for i, sid := range sids {
		keys[i] = s.keySession(sid)
	}
	vals, err := s.rdb.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}
	var out []Record
	var stale []any
	for i, v := range vals {
		str, ok := v.(string)
		if !ok {
			stale = append(stale, sids[i])
			continue
		}
		r, err := decode([]byte(str))
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if len(stale) > 0 {
		s.rdb.SRem(ctx, s.keyUser(userID), stale...)
	}
	return out, nil
}

func (s *Store) History(ctx context.Context, userID int64) ([]Ended, error) {
	vals, err := s.rdb.LRange(ctx, s.keyHistory(userID), 0, s.history-1).Result()
	if err != nil {
		return nil, err
	}
	out := make([]Ended, 0, len(vals))
	for _, v := range vals {
		var e Ended
		if json.Unmarshal([]byte(v), &e) == nil {
			out = append(out, e)
		}
	}
	return out, nil
}

func (s *Store) UpdateUser(ctx context.Context, user types.User) ([]string, error) {
	recs, err := s.List(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	var sids []string
	for _, r := range recs {
		r.User = user
		b, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		if err := s.rdb.SetArgs(ctx, s.keySession(r.SID), b, redis.SetArgs{KeepTTL: true, Mode: "XX"}).Err(); err != nil && !errors.Is(err, redis.Nil) {
			return nil, err
		}
		sids = append(sids, r.SID)
	}
	if len(sids) > 0 {
		err = s.publish(ctx, Event{Type: constants.EventChanged, UserID: user.ID, SIDs: sids})
	}
	return sids, err
}

func (s *Store) publish(ctx context.Context, e Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return s.rdb.Publish(ctx, s.Channel(), b).Err()
}
