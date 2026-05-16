package source

import "github.com/pridhvi/nox/internal/models"

type Extractor interface {
	Detect(repoPath string) bool
	Language() string
	Framework() string
	Extract(repoPath, sessionID string) ([]models.SourceFinding, error)
}
