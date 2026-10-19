package broker

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// One audit line. Field names and destinations only; never a secret value,
// a session token, or a password. The log file is 0600 and stays out of the
// journal, which other local users may be able to read.
type AuditEvent struct {
	Time      time.Time `json:"time"`
	Event     string    `json:"event"`
	RequestID string    `json:"request_id,omitempty"`
	Kind      string    `json:"kind,omitempty"`
	RPID      string    `json:"rp_id,omitempty"`
	ItemID    string    `json:"item_id,omitempty"`
	ItemName  string    `json:"item_name,omitempty"`
	Fields    []string  `json:"fields,omitempty"`
	Session   string    `json:"session,omitempty"`
	Origin    string    `json:"origin,omitempty"`
	Outcome   string    `json:"outcome,omitempty"`
}

type AuditLog struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

func OpenAuditLog(path string) (*AuditLog, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	return &AuditLog{file: file, enc: json.NewEncoder(file)}, nil
}

func (l *AuditLog) Write(event AuditEvent) {
	event.Time = time.Now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(event)
}

func (l *AuditLog) Close() error { return l.file.Close() }
