package models

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

var (
	newRandomUUID     = uuid.NewRandom
	fallbackIDCounter atomic.Uint64
)

func NewIDWithError() (string, error) {
	id, err := newRandomUUID()
	if err != nil {
		return "", fmt.Errorf("generate random id: %w", err)
	}
	return id.String(), nil
}

func NewID() string {
	id, err := NewIDWithError()
	if err == nil {
		return id
	}
	return fallbackID()
}

func fallbackID() string {
	seed := fmt.Sprintf("%d:%d:%d", time.Now().UnixNano(), os.Getpid(), fallbackIDCounter.Add(1))
	sum := sha256.Sum256([]byte(seed))
	id := uuid.UUID(sum[:16])
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id.String()
}
