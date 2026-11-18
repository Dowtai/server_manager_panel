package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"awgpanel/internal/domain"
	"awgpanel/internal/storage/dbsql"
	"awgpanel/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

type Repository interface {
	View(context.Context, func(*domain.State) error) error
	Update(context.Context, func(*domain.State) error) error
}
type Store struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, url string) (*Store, error) {
	p, e := pgxpool.New(ctx, url)
	if e != nil {
		return nil, e
	}
	if e = p.Ping(ctx); e != nil {
		p.Close()
		return nil, e
	}
	return &Store{p}, nil
}
func (s *Store) Close() { s.Pool.Close() }
func Migrate(ctx context.Context, url string) error {
	c, e := pgx.ParseConfig(url)
	if e != nil {
		return e
	}
	db := stdlib.OpenDB(*c)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if e = goose.SetDialect("postgres"); e != nil {
		return e
	}
	return goose.UpContext(ctx, db, ".")
}

// Explicit, typed bindings avoid depending on struct field order or reflection.
// Table names are source constants; no request input is interpolated into SQL.
type entityTable struct {
	name    string
	load    func(context.Context, pgx.Tx) error
	records func() (map[string][]byte, error)
}

func bind[T any](name string, values map[string]T) entityTable {
	return entityTable{
		name: name,
		load: func(ctx context.Context, tx pgx.Tx) error {
			rows, e := tx.Query(ctx, "SELECT id::text,data FROM "+pgx.Identifier{name}.Sanitize()+" ORDER BY id")
			if e != nil {
				return e
			}
			defer rows.Close()
			for rows.Next() {
				var id string
				var raw []byte
				if e = rows.Scan(&id, &raw); e != nil {
					return e
				}
				var value T
				if e = json.Unmarshal(raw, &value); e != nil {
					return fmt.Errorf("decode %s: %w", name, e)
				}
				values[id] = value
			}
			return rows.Err()
		},
		records: func() (map[string][]byte, error) {
			result := make(map[string][]byte, len(values))
			for id, value := range values {
				raw, e := json.Marshal(value)
				if e != nil {
					return nil, e
				}
				result[id] = raw
			}
			return result, nil
		},
	}
}
func collections(s *domain.State) []entityTable {
	return []entityTable{
		bind("pools", s.Pools), bind("servers", s.Servers), bind("instances", s.Instances), bind("endpoints", s.Endpoints), bind("placements", s.Placements), bind("deployments", s.Deployments), bind("users", s.Users), bind("identities", s.Identities), bind("grants", s.Grants), bind("devices", s.Devices), bind("operations", s.Operations), bind("audit", s.Audit),
	}
}
func load(ctx context.Context, tx pgx.Tx) (domain.State, error) {
	s := domain.NewState()
	for _, table := range collections(&s) {
		if e := table.load(ctx, tx); e != nil {
			return s, e
		}
	}
	return s, nil
}
func (s *Store) View(ctx context.Context, fn func(*domain.State) error) error {
	tx, e := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	v, e := load(ctx, tx)
	if e != nil {
		return e
	}
	return fn(&v)
}
func (s *Store) Update(ctx context.Context, fn func(*domain.State) error) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	if e = dbsql.New(tx).LockState(ctx); e != nil {
		return e
	}
	v, e := load(ctx, tx)
	if e != nil {
		return e
	}
	before := map[string]map[string][]byte{}
	for _, table := range collections(&v) {
		before[table.name], e = table.records()
		if e != nil {
			return e
		}
	}
	if e = fn(&v); e != nil {
		return e
	}
	after := map[string]map[string][]byte{}
	tables := collections(&v)
	for _, table := range tables {
		after[table.name], e = table.records()
		if e != nil {
			return e
		}
	}
	// Remove children first, then insert/update parents first. Unchanged rows are not rewritten.
	for n := len(tables) - 1; n >= 0; n-- {
		name := tables[n].name
		for id := range before[name] {
			if _, ok := after[name][id]; !ok {
				if _, e = tx.Exec(ctx, "DELETE FROM "+pgx.Identifier{name}.Sanitize()+" WHERE id=$1", id); e != nil {
					return e
				}
			}
		}
	}
	for _, table := range tables {
		for id, raw := range after[table.name] {
			if bytes.Equal(before[table.name][id], raw) {
				continue
			}
			if _, e = tx.Exec(ctx, "INSERT INTO "+pgx.Identifier{table.name}.Sanitize()+"(id,data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data", id, raw); e != nil {
				return fmt.Errorf("persist %s: %w", table.name, e)
			}
		}
	}
	return tx.Commit(ctx)
}
