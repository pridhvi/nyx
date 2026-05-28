package source

import "github.com/pridhvi/nyx/internal/models"

type GoExtractor struct{}

func (e GoExtractor) extractor() genericExtractor {
	return genericExtractor{language: "go", framework: "go", extensions: []string{".go"}, markers: []string{"go.mod"}}
}
func (e GoExtractor) Detect(repoPath string) bool { return e.extractor().Detect(repoPath) }
func (e GoExtractor) Language() string            { return "go" }
func (e GoExtractor) Framework() string           { return "go" }
func (e GoExtractor) Extract(repoPath, sessionID string) ([]models.SourceFinding, error) {
	return e.extractor().Extract(repoPath, sessionID)
}
