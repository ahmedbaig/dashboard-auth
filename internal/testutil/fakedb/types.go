package fakedb

import "sync"

type row = map[string]any

type DB struct {
	mu     sync.Mutex
	tables map[string][]row
	nextID map[string]int64
	unique map[string][]string
}
