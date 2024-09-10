package datastore

import (
	"errors"
	statefs "github.com/datadog/stratus-red-team/v2/internal/state/filesystem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestDataStoreHasKeyWhenKeyExists(t *testing.T) {
	fsMock := new(statefs.FileSystemMock)
	fsMock.On("FileExists", mock.Anything).Return(true)
	fsMock.On("ReadFile", mock.Anything).Return([]byte(`{"key1": "value1"}`), nil)

	dataStore := &FileSystemDataStore{
		FileSystem:              fsMock,
		TechniqueStateDirectory: "/root/.stratus-red-team/my-technique",
	}
	err := dataStore.Load()
	assert.Nil(t, err)
	assert.True(t, dataStore.Has("key1"))
	assert.False(t, dataStore.Has("key2"))
}

func TestDataStoreGetKeyWhenKeyExists(t *testing.T) {
	fsMock := new(statefs.FileSystemMock)
	fsMock.On("FileExists", mock.Anything).Return(true)
	fsMock.On("ReadFile", mock.Anything).Return([]byte(`{"key1": "value1"}`), nil)

	dataStore := &FileSystemDataStore{
		FileSystem:              fsMock,
		TechniqueStateDirectory: "/root/.stratus-red-team/my-technique",
	}
	err := dataStore.Load()
	assert.Nil(t, err)

	value, err := dataStore.Get("key1")
	assert.Nil(t, err)
	assert.Equal(t, "value1", value)
}

func TestDataStoreGetKeyWhenKeyDoesNotExist(t *testing.T) {
	fsMock := new(statefs.FileSystemMock)
	fsMock.On("FileExists", mock.Anything).Return(true)
	fsMock.On("ReadFile", mock.Anything).Return([]byte(`{"key1": "value1"}`), nil)

	dataStore := &FileSystemDataStore{
		FileSystem:              fsMock,
		TechniqueStateDirectory: "/root/.stratus-red-team/my-technique",
	}
	err := dataStore.Load()
	assert.Nil(t, err)

	_, err = dataStore.Get("key2")
	assert.NotNil(t, err)
}

func TestDataStoreSetKeyWhenFileDoesNotExist(t *testing.T) {
	fsMock := new(statefs.FileSystemMock)
	fsMock.On("FileExists", mock.Anything).Return(false)
	fsMock.On("WriteFile", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	dataStore := &FileSystemDataStore{
		FileSystem:              fsMock,
		TechniqueStateDirectory: "/root/.stratus-red-team/my-technique",
		state:                   map[string]string{},
	}
	err := dataStore.Set("key1", "value1")
	assert.Nil(t, err)

	fsMock.AssertCalled(t, "WriteFile", "/root/.stratus-red-team/my-technique/data.json", []byte(`{"key1":"value1"}`), mock.Anything)
}

func TestDataStoreSetKeyWhenFileExists(t *testing.T) {
	fsMock := new(statefs.FileSystemMock)
	fsMock.On("FileExists", mock.Anything).Return(true)
	fsMock.On("ReadFile", mock.Anything).Return([]byte(`{"key1": "value1"}`), nil)
	fsMock.On("WriteFile", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	dataStore := &FileSystemDataStore{
		FileSystem:              fsMock,
		TechniqueStateDirectory: "/root/.stratus-red-team/my-technique",
	}
	err := dataStore.Load()
	assert.Nil(t, err)

	err = dataStore.Set("key2", "value2")
	assert.Nil(t, err)

	fsMock.AssertCalled(t, "WriteFile", "/root/.stratus-red-team/my-technique/data.json", []byte(`{"key1":"value1","key2":"value2"}`), mock.Anything)
}

func TestDataStoreSetKeyWhenWriteFileFails(t *testing.T) {
	fsMock := new(statefs.FileSystemMock)
	fsMock.On("FileExists", mock.Anything).Return(false)
	fsMock.On("WriteFile", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("write error"))

	dataStore := &FileSystemDataStore{
		FileSystem:              fsMock,
		TechniqueStateDirectory: "/root/.stratus-red-team/my-technique",
		state:                   map[string]string{},
	}
	err := dataStore.Set("key1", "value1")
	assert.NotNil(t, err)
}

func TestDataStoreClearKeyWhenKeyExists(t *testing.T) {
	fsMock := new(statefs.FileSystemMock)
	fsMock.On("FileExists", mock.Anything).Return(true)
	fsMock.On("ReadFile", mock.Anything).Return([]byte(`{"key1": "value1"}`), nil)
	fsMock.On("WriteFile", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	dataStore := &FileSystemDataStore{
		FileSystem:              fsMock,
		TechniqueStateDirectory: "/root/.stratus-red-team/my-technique",
		state:                   make(map[string]string),
	}
	err := dataStore.Load()
	assert.Nil(t, err)

	err = dataStore.Clear("key1")
	assert.Nil(t, err)
	assert.False(t, dataStore.Has("key1"))

	fsMock.AssertCalled(t, "WriteFile", "/root/.stratus-red-team/my-technique/data.json", []byte(`{}`), mock.Anything)
}

func TestDataStoreClearKeyWhenKeyDoesNotExist(t *testing.T) {
	fsMock := new(statefs.FileSystemMock)
	fsMock.On("FileExists", mock.Anything).Return(true)
	fsMock.On("ReadFile", mock.Anything).Return([]byte(`{"key1": "value1"}`), nil)

	dataStore := &FileSystemDataStore{
		FileSystem:              fsMock,
		TechniqueStateDirectory: "/root/.stratus-red-team/my-technique",
		state:                   make(map[string]string),
	}
	err := dataStore.Load()
	assert.Nil(t, err)

	err = dataStore.Clear("key2")
	assert.NotNil(t, err)
	assert.Equal(t, "key not found", err.Error())
}

func TestDataStoreClearAllKeyWhenKeyExists(t *testing.T) {
	fsMock := new(statefs.FileSystemMock)
	fsMock.On("FileExists", mock.Anything).Return(true)
	fsMock.On("ReadFile", mock.Anything).Return([]byte(`{"key1": "value1", "key2": "value2"}`), nil)
	fsMock.On("WriteFile", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	dataStore := &FileSystemDataStore{
		FileSystem:              fsMock,
		TechniqueStateDirectory: "/root/.stratus-red-team/my-technique",
		state:                   make(map[string]string),
	}
	err := dataStore.Load()
	assert.Nil(t, err)

	err = dataStore.ClearAll()
	assert.False(t, dataStore.Has("key1"))
	assert.False(t, dataStore.Has("key2"))

	fsMock.AssertCalled(t, "WriteFile", "/root/.stratus-red-team/my-technique/data.json", []byte(`{}`), mock.Anything)
}
