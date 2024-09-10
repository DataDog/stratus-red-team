package datastore

import (
	"encoding/json"
	"errors"
	state "github.com/datadog/stratus-red-team/v2/internal/state/filesystem"
	"path/filepath"
)

type DataStore interface {
	Has(key string) bool
	Get(key string) (string, error)
	Set(key string, value string) error
	Clear(key string) error
	ClearAll() error
}

const DataStoreFileName = "data.json"

// type check
var _ DataStore = &FileSystemDataStore{}

type FileSystemDataStore struct {
	FileSystem              state.FileSystem
	TechniqueStateDirectory string
	state                   map[string]string
}

func (m *FileSystemDataStore) Load() error {
	if m.FileSystem.FileExists(m.getDataStoreFilePath()) {
		data, err := m.FileSystem.ReadFile(m.getDataStoreFilePath())
		if err != nil {
			return errors.New("unable to read data store file: " + err.Error())
		}
		err = json.Unmarshal(data, &m.state)
		if err != nil {
			return errors.New("unable to unmarshal data store file: " + err.Error())
		}
	} else {
		// don't create it if it doesn't exist, to avoid creating unnecessary files
		m.state = make(map[string]string)
	}
	return nil
}

func (m *FileSystemDataStore) getDataStoreFilePath() string {
	return filepath.Join(m.TechniqueStateDirectory, DataStoreFileName)
}

func (m *FileSystemDataStore) Has(key string) bool {
	_, ok := m.state[key]
	return ok
}

func (m *FileSystemDataStore) Get(key string) (string, error) {
	if !m.Has(key) {
		return "", errors.New("key not found")
	}
	return m.state[key], nil
}

func (m *FileSystemDataStore) Set(key string, value string) error {
	m.state[key] = value
	return m.save()
}

func (m *FileSystemDataStore) Clear(key string) error {
	if !m.Has(key) {
		return errors.New("key not found")
	}
	delete(m.state, key)
	return m.save()
}

func (m *FileSystemDataStore) ClearAll() error {
	m.state = make(map[string]string)
	return m.save()
}

func (m *FileSystemDataStore) save() error {
	data, err := json.Marshal(m.state)
	if err != nil {
		return errors.New("unable to marshal data store file: " + err.Error())
	}

	err = m.FileSystem.WriteFile(m.getDataStoreFilePath(), data, 0744)
	if err != nil {
		return errors.New("unable to write data store file: " + err.Error())
	}

	return nil
}
