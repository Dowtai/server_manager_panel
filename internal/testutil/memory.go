// Package testutil supplies an isolated transactional repository for domain/API tests.
package testutil

import (
	"awgpanel/internal/domain"
	"context"
	"encoding/json"
	"sync"
)

type Memory struct {
	Mu    sync.Mutex
	State domain.State
}

func New() *Memory { return &Memory{State: domain.NewState()} }
func clone(s domain.State) domain.State {
	b, _ := json.Marshal(s)
	v := domain.NewState()
	_ = json.Unmarshal(b, &v)
	return v
}
func (m *Memory) View(_ context.Context, fn func(*domain.State) error) error {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	s := clone(m.State)
	return fn(&s)
}
func (m *Memory) Update(_ context.Context, fn func(*domain.State) error) error {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	s := clone(m.State)
	if e := fn(&s); e != nil {
		return e
	}
	m.State = s
	return nil
}
