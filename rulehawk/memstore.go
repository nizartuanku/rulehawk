package rulehawk

import (
	"sort"
	"strings"
	"sync"
)

// MemStore is an in-memory config Store for tests and ephemeral runs.
type MemStore struct {
	mu   sync.RWMutex
	byID map[string]Config
}

// NewMemStore builds an empty in-memory store.
func NewMemStore() *MemStore { return &MemStore{byID: map[string]Config{}} }

func (m *MemStore) PutConfig(c Config) error {
	c.HasBase = strings.TrimSpace(c.Baseline) != ""
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[c.Name] = c
	return nil
}

func (m *MemStore) GetConfig(name string) (Config, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.byID[name]
	return c, ok, nil
}

func (m *MemStore) ListConfigs() ([]Config, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Config, 0, len(m.byID))
	for _, c := range m.byID {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *MemStore) DeleteConfig(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byID, name)
	return nil
}
