package pipeline

import (
	"errors"
	"sync"
)

// Session is a thread-safe key-value store.
type Session struct {
	data map[string]interface{}
	mu   sync.RWMutex
}

var (
	globalSession *Session
	globalOnce    sync.Once
)

// New creates a new Session instance.
func New() *Session {
	return &Session{
		data: make(map[string]interface{}),
	}
}

// Global returns the global singleton Session instance.
func Global() *Session {
	globalOnce.Do(func() {
		globalSession = New()
	})
	return globalSession
}

// Set adds a key-value pair (error if key exists).
func (s *Session) Set(key string, value interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[key]; exists {
		return errors.New("key already exists")
	}
	s.data[key] = value
	return nil
}

// MustSet sets a key-value pair (panics on error).
func (s *Session) MustSet(key string, value interface{}) {
	if err := s.Set(key, value); err != nil {
		panic(err)
	}
}

// Update modifies an existing key-value pair.
func (s *Session) Update(key string, value interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[key]; !exists {
		return errors.New("key not found")
	}
	s.data[key] = value
	return nil
}

// Get retrieves a value by key.
func (s *Session) Get(key string) (interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	val, exists := s.data[key]
	if !exists {
		return nil, errors.New("key not found")
	}
	return val, nil
}

// MustGet retrieves a value (panics if key missing).
func (s *Session) MustGet(key string) interface{} {
	val, err := s.Get(key)
	if err != nil {
		panic(err)
	}
	return val
}

// GetString retrieves a string value (with type assertion).
func (s *Session) GetString(key string) (string, error) {
	val, err := s.Get(key)
	if err != nil {
		return "", err
	}
	str, ok := val.(string)
	if !ok {
		return "", errors.New("value is not a string")
	}
	return str, nil
}

// Delete removes a key-value pair.
func (s *Session) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[key]; !exists {
		return errors.New("key not found")
	}
	delete(s.data, key)
	return nil
}

// Clear removes all key-value pairs.
func (s *Session) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = make(map[string]interface{})
}
