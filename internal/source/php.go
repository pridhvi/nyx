package source

import "github.com/pridhvi/nyx/internal/models"

type PHPExtractor struct{}

func (e PHPExtractor) extractor() genericExtractor {
	return genericExtractor{language: "php", framework: "php", extensions: []string{".php"}, markers: []string{"composer.json"}}
}
func (e PHPExtractor) Detect(repoPath string) bool { return e.extractor().Detect(repoPath) }
func (e PHPExtractor) Language() string            { return "php" }
func (e PHPExtractor) Framework() string           { return "php" }
func (e PHPExtractor) Extract(repoPath, sessionID string) ([]models.SourceFinding, error) {
	return e.extractor().Extract(repoPath, sessionID)
}
