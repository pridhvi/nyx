package source

import "github.com/pridhvi/nyx/internal/models"

type PythonExtractor struct{}

func (e PythonExtractor) extractor() genericExtractor {
	return genericExtractor{language: "python", framework: "python", extensions: []string{".py"}, markers: []string{"requirements.txt", "pyproject.toml", "setup.py"}}
}
func (e PythonExtractor) Detect(repoPath string) bool { return e.extractor().Detect(repoPath) }
func (e PythonExtractor) Language() string            { return "python" }
func (e PythonExtractor) Framework() string           { return "python" }
func (e PythonExtractor) Extract(repoPath, sessionID string) ([]models.SourceFinding, error) {
	return e.extractor().Extract(repoPath, sessionID)
}
