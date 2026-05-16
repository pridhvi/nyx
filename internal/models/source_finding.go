package models

import "time"

type SourceFindingKind string

const (
	SourceKindRoute               SourceFindingKind = "route"
	SourceKindParameter           SourceFindingKind = "parameter"
	SourceKindSQLSink             SourceFindingKind = "sql_sink"
	SourceKindFileUpload          SourceFindingKind = "file_upload"
	SourceKindUnprotectedRoute    SourceFindingKind = "unprotected_route"
	SourceKindSecret              SourceFindingKind = "secret"
	SourceKindSSRFSink            SourceFindingKind = "ssrf_sink"
	SourceKindDeserialisationSink SourceFindingKind = "deserialisation_sink"
	SourceKindAuthMiddleware      SourceFindingKind = "auth_middleware"
)

type SourceFinding struct {
	ID                 string            `json:"id"`
	SessionID          string            `json:"session_id"`
	Kind               SourceFindingKind `json:"kind"`
	Language           string            `json:"language"`
	Framework          string            `json:"framework"`
	FilePath           string            `json:"file_path"`
	LineNumber         int               `json:"line_number"`
	Value              string            `json:"value"`
	Method             string            `json:"method"`
	Context            string            `json:"context"`
	Notes              string            `json:"notes"`
	ConfirmedByDynamic bool              `json:"confirmed_by_dynamic"`
	CreatedAt          time.Time         `json:"created_at"`
}
