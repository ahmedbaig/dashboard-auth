package fakedb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ahmedbaig/go-backend-db"
)

var errUnsupported = errors.New("fakedb: unsupported")

func New() *DB {
	return &DB{
		tables: map[string][]row{},
		nextID: map[string]int64{},
		unique: map[string][]string{"users": {"email"}, "password_credentials": {"user_id"}},
	}
}

func (d *DB) Client() *db.Client { return db.NewClientWith(d) }

func (d *DB) Set(table string, where map[string]any, changes map[string]any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range d.tables[table] {
		if matches(r, where) {
			for k, v := range changes {
				r[k] = v
			}
		}
	}
}

func normalize(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func eqWhere(w db.Where) (map[string]any, error) {
	if len(w.And) > 0 || len(w.Or) > 0 || w.Not != nil {
		return nil, errUnsupported
	}
	out := map[string]any{}
	for f, c := range w.Fields {
		v, ok := c[db.OpEq]
		if !ok || len(c) != 1 {
			return nil, fmt.Errorf("%w: %s", errUnsupported, f)
		}
		out[f] = normalize(v)
	}
	return out, nil
}

func matches(r row, where map[string]any) bool {
	for k, v := range where {
		if fmt.Sprint(r[k]) != fmt.Sprint(v) {
			return false
		}
	}
	return true
}

func decodeRows(raw json.RawMessage) ([]row, error) {
	var many []row
	if err := json.Unmarshal(raw, &many); err == nil {
		return many, nil
	}
	var one row
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return []row{one}, nil
}

func result(v any) (db.Result, error) {
	b, err := json.Marshal(v)
	return db.Result{Data: b}, err
}

func counted(n int) db.Result {
	c := int64(n)
	return db.Result{Count: &c}
}

func (d *DB) insert(table string, r row) (row, error) {
	for _, f := range d.unique[table] {
		for _, existing := range d.tables[table] {
			if fmt.Sprint(existing[f]) == fmt.Sprint(r[f]) {
				return nil, db.ErrConflict
			}
		}
	}
	if id, ok := r["id"]; !ok || id == nil || fmt.Sprint(id) == "0" {
		if table == "users" {
			d.nextID[table]++
			r["id"] = float64(d.nextID[table])
		}
	}
	d.tables[table] = append(d.tables[table], r)
	return r, nil
}

func (d *DB) query(q db.Query) (db.Result, error) {
	where, err := eqWhere(q.Params.Where)
	if err != nil {
		return db.Result{}, err
	}
	rows := d.tables[q.Service]
	switch q.Method {
	case db.FindOne, db.FindFirst:
		for _, r := range rows {
			if matches(r, where) {
				return result(r)
			}
		}
		return db.Result{}, db.ErrNotFound
	case db.FindMany:
		out := []row{}
		for _, r := range rows {
			if matches(r, where) {
				out = append(out, r)
			}
		}
		return result(out)
	case db.Count:
		n := 0
		for _, r := range rows {
			if matches(r, where) {
				n++
			}
		}
		return counted(n), nil
	case db.Create, db.CreateMany:
		in, err := decodeRows(q.Params.Data)
		if err != nil {
			return db.Result{}, err
		}
		var last row
		for _, r := range in {
			if last, err = d.insert(q.Service, r); err != nil {
				return db.Result{}, err
			}
		}
		if q.Method == db.CreateMany {
			return counted(len(in)), nil
		}
		return result(last)
	case db.Update:
		var changes row
		if err := json.Unmarshal(q.Params.Data, &changes); err != nil {
			return db.Result{}, err
		}
		for _, r := range rows {
			if matches(r, where) {
				for k, v := range changes {
					r[k] = v
				}
				return result(r)
			}
		}
		return db.Result{}, db.ErrNotFound
	case db.Upsert:
		var create, changes row
		if err := json.Unmarshal(q.Params.Create, &create); err != nil {
			return db.Result{}, err
		}
		if err := json.Unmarshal(q.Params.Data, &changes); err != nil {
			return db.Result{}, err
		}
		key := map[string]any{}
		for _, f := range q.Params.Conflict {
			key[f] = create[f]
		}
		for _, r := range rows {
			if matches(r, key) {
				for k, v := range changes {
					r[k] = v
				}
				return result(r)
			}
		}
		r, err := d.insert(q.Service, create)
		if err != nil {
			return db.Result{}, err
		}
		return result(r)
	case db.DeleteMany:
		kept := rows[:0:0]
		n := 0
		for _, r := range rows {
			if matches(r, where) {
				n++
				continue
			}
			kept = append(kept, r)
		}
		d.tables[q.Service] = kept
		return counted(n), nil
	}
	return db.Result{}, fmt.Errorf("%w: %s", errUnsupported, q.Method)
}

func (d *DB) Query(_ context.Context, q db.Query) (db.Result, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.query(q)
}

func (d *DB) Transaction(_ context.Context, tx db.Transaction) (db.TransactionResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out db.TransactionResult
	for _, q := range tx.Queries {
		r, err := d.query(q)
		if err != nil {
			return db.TransactionResult{}, err
		}
		out.Results = append(out.Results, r)
	}
	return out, nil
}

func (d *DB) Capabilities(context.Context) (db.Capabilities, error) { return db.Capabilities{}, nil }

func (d *DB) KV(context.Context, string, db.KVOp, db.KVRequest) (db.KVResult, error) {
	return db.KVResult{}, errUnsupported
}

func (d *DB) Docs(context.Context, string, string, db.DocsOp, db.DocsRequest) (db.DocsResult, error) {
	return db.DocsResult{}, errUnsupported
}

func (d *DB) Track(context.Context, string, db.TrackRequest) (db.TrackResult, error) {
	return db.TrackResult{}, errUnsupported
}

func (d *DB) DAU(context.Context, string, string, string) ([]db.DAUPoint, error) {
	return nil, errUnsupported
}
