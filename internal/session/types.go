package session

import (
	"time"

	"github.com/ahmedbaig/go-backend-types"
	"github.com/redis/go-redis/v9"
)

type Caller struct {
	User types.User
	SID  string
}

type Client struct {
	IP        string
	UserAgent string
}

type callerKey struct{}

type attemptKey struct{}

type Lockout struct {
	rdb    redis.UniversalClient
	prefix string
	max    int64
	window time.Duration
}

type Record struct {
	SID         string     `json:"sid"`
	UserID      int64      `json:"userId"`
	User        types.User `json:"user"`
	IP          string     `json:"ip"`
	UserAgent   string     `json:"userAgent"`
	Device      string     `json:"device"`
	Browser     string     `json:"browser"`
	CreatedAt   time.Time  `json:"createdAt"`
	LastSeenAt  time.Time  `json:"lastSeenAt"`
	RefreshHash string     `json:"refreshHash"`
	PrevHash    string     `json:"prevHash,omitempty"`
	RotatedAt   time.Time  `json:"rotatedAt,omitzero"`
}

type Ended struct {
	Device    string    `json:"device"`
	Browser   string    `json:"browser"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"createdAt"`
	EndedAt   time.Time `json:"endedAt"`
	Reason    string    `json:"reason"`
}

type Event struct {
	Type   string   `json:"type"`
	UserID int64    `json:"userId"`
	SIDs   []string `json:"sids"`
	Reason string   `json:"reason,omitempty"`
}

type Store struct {
	rdb     redis.UniversalClient
	prefix  string
	ttl     time.Duration
	history int64
	now     func() time.Time
}

type Options struct {
	Prefix      string
	TTL         time.Duration
	HistorySize int
	Now         func() time.Time
}

type Rotation struct {
	Record  Record
	Payload []byte
}
