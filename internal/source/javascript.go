package source

import "github.com/pridhvi/nyx/internal/models"

type JavaScriptExtractor struct{}

func (e JavaScriptExtractor) extractor() genericExtractor {
	return genericExtractor{language: "javascript", framework: "javascript", extensions: []string{".js", ".jsx", ".ts", ".tsx"}, markers: []string{"package.json"}}
}
func (e JavaScriptExtractor) Detect(repoPath string) bool { return e.extractor().Detect(repoPath) }
func (e JavaScriptExtractor) Language() string            { return "javascript" }
func (e JavaScriptExtractor) Framework() string           { return "javascript" }
func (e JavaScriptExtractor) Extract(repoPath, sessionID string) ([]models.SourceFinding, error) {
	return e.extractor().Extract(repoPath, sessionID)
}
