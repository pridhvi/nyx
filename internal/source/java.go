package source

import "github.com/pridhvi/nyx/internal/models"

type JavaExtractor struct{}

func (e JavaExtractor) extractor() genericExtractor {
	return genericExtractor{language: "java", framework: "java", extensions: []string{".java"}, markers: []string{"pom.xml", "build.gradle"}}
}
func (e JavaExtractor) Detect(repoPath string) bool { return e.extractor().Detect(repoPath) }
func (e JavaExtractor) Language() string            { return "java" }
func (e JavaExtractor) Framework() string           { return "java" }
func (e JavaExtractor) Extract(repoPath, sessionID string) ([]models.SourceFinding, error) {
	return e.extractor().Extract(repoPath, sessionID)
}
