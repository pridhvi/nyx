package source

import "github.com/pridhvi/nyx/internal/models"

type RubyExtractor struct{}

func (e RubyExtractor) extractor() genericExtractor {
	return genericExtractor{language: "ruby", framework: "ruby", extensions: []string{".rb"}, markers: []string{"Gemfile"}}
}
func (e RubyExtractor) Detect(repoPath string) bool { return e.extractor().Detect(repoPath) }
func (e RubyExtractor) Language() string            { return "ruby" }
func (e RubyExtractor) Framework() string           { return "ruby" }
func (e RubyExtractor) Extract(repoPath, sessionID string) ([]models.SourceFinding, error) {
	return e.extractor().Extract(repoPath, sessionID)
}
