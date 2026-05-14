package cve

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kanini/nox/internal/models"
)

const (
	EnvOfflinePath  = "NOX_CVE_OFFLINE_PATH"
	EnvEnableRemote = "NOX_CVE_ENABLE_REMOTE"
	DefaultCacheTTL = 24 * time.Hour
)

type Advisory struct {
	CVEID            string   `json:"cve_id"`
	Product          string   `json:"product"`
	AffectedVersion  string   `json:"affected_version"`
	FixedVersion     string   `json:"fixed_version"`
	CVSSv3Score      float64  `json:"cvss_v3_score"`
	CVSSv3Vector     string   `json:"cvss_v3_vector"`
	Description      string   `json:"description"`
	PatchAvailable   bool     `json:"patch_available"`
	ExploitAvailable bool     `json:"exploit_available"`
	References       []string `json:"references"`
	Source           string   `json:"source"`
}

type Source interface {
	Name() string
	Search(ctx context.Context, product, version string) ([]Advisory, error)
}

type Correlator struct {
	sources []Source
	cache   *Cache
}

type Result struct {
	Matches []models.CVEMatch
	Vectors []models.AttackVector
}

func NewCorrelator(sources []Source, cache *Cache) *Correlator {
	if cache == nil {
		cache = NewCache(DefaultCacheTTL)
	}
	return &Correlator{sources: sources, cache: cache}
}

func NewDefaultCorrelator() *Correlator {
	var sources []Source
	if path := strings.TrimSpace(os.Getenv(EnvOfflinePath)); path != "" {
		sources = append(sources, NewOfflineSource(path))
	}
	sources = append(sources, EmbeddedSource{})
	if strings.EqualFold(os.Getenv(EnvEnableRemote), "true") {
		client := &http.Client{Timeout: 10 * time.Second}
		sources = append(sources,
			NewNVDClient(client, ""),
			NewOSVClient(client, ""),
			NewCIRCLClient(client, ""),
			NewVulnersClient(client, ""),
			NewGitHubAdvisoryClient(client, ""),
		)
	}
	return NewCorrelator(sources, NewCache(DefaultCacheTTL))
}

func (c *Correlator) Correlate(ctx context.Context, session models.Session, targets []models.Target, findings []models.Finding) (Result, error) {
	if c == nil {
		return Result{}, nil
	}
	var result Result
	seen := map[string]bool{}
	for _, target := range targets {
		for _, tech := range target.Technologies {
			if strings.TrimSpace(tech.Version) == "" {
				continue
			}
			advisories, err := c.search(ctx, tech.Name, tech.Version)
			if err != nil {
				return result, err
			}
			for _, advisory := range advisories {
				match := matchFromAdvisory(advisory)
				match.ID = models.NewID()
				match.TechnologyID = tech.ID
				match.AffectedVersion = firstNonEmpty(advisory.AffectedVersion, tech.Version)
				match.ConfidenceScore = confidenceFor(tech.Name, tech.Version, advisory)
				key := "tech:" + tech.ID + ":" + match.CVEID
				if seen[key] || match.ConfidenceScore <= 0 {
					continue
				}
				seen[key] = true
				result.Matches = append(result.Matches, match)
				if vector := vectorFor(session.ID, match, "technology "+tech.Name); vector.ID != "" {
					result.Vectors = append(result.Vectors, vector)
				}
			}
		}
	}
	for _, finding := range findings {
		for _, cveID := range CVEIDs(finding.Title + " " + finding.Description + " " + finding.EvidenceRaw + " " + finding.EvidenceNormalized) {
			key := "finding:" + finding.ID + ":" + cveID
			if seen[key] {
				continue
			}
			seen[key] = true
			match := models.CVEMatch{
				ID:              models.NewID(),
				FindingID:       finding.ID,
				CVEID:           cveID,
				Description:     "CVE identifier observed in scanner evidence.",
				Source:          "finding-evidence",
				ConfidenceScore: 0.6,
				References:      []string{"https://nvd.nist.gov/vuln/detail/" + cveID},
			}
			result.Matches = append(result.Matches, match)
		}
	}
	sort.Slice(result.Matches, func(i, j int) bool { return result.Matches[i].CVEID < result.Matches[j].CVEID })
	return result, nil
}

func (c *Correlator) search(ctx context.Context, product, version string) ([]Advisory, error) {
	key := normalizeProduct(product) + "@" + strings.TrimSpace(version)
	if advisories, ok := c.cache.Get(key); ok {
		return advisories, nil
	}
	var all []Advisory
	for _, source := range c.sources {
		advisories, err := source.Search(ctx, product, version)
		if err != nil {
			continue
		}
		all = append(all, advisories...)
	}
	all = dedupeAdvisories(all)
	c.cache.Set(key, all)
	return all, nil
}

func matchFromAdvisory(advisory Advisory) models.CVEMatch {
	return models.CVEMatch{
		CVEID:            advisory.CVEID,
		CVSSv3Score:      advisory.CVSSv3Score,
		CVSSv3Vector:     advisory.CVSSv3Vector,
		Description:      advisory.Description,
		AffectedVersion:  advisory.AffectedVersion,
		FixedVersion:     advisory.FixedVersion,
		PatchAvailable:   advisory.PatchAvailable || advisory.FixedVersion != "",
		ExploitAvailable: advisory.ExploitAvailable,
		References:       advisory.References,
		Source:           firstNonEmpty(advisory.Source, "cve"),
	}
}

func confidenceFor(product, version string, advisory Advisory) float64 {
	if !strings.Contains(normalizeProduct(advisory.Product), normalizeProduct(product)) &&
		!strings.Contains(normalizeProduct(product), normalizeProduct(advisory.Product)) {
		return 0
	}
	if version == "" {
		return 0.4
	}
	if advisory.AffectedVersion == "" {
		return 0.55
	}
	if advisory.AffectedVersion == version {
		return 0.95
	}
	if versionInRange(version, advisory.AffectedVersion) {
		return 0.85
	}
	return 0.45
}

func vectorFor(sessionID string, match models.CVEMatch, subject string) models.AttackVector {
	if !match.ExploitAvailable || match.CVSSv3Score < 7 {
		return models.AttackVector{}
	}
	return models.AttackVector{
		ID:            models.NewID(),
		SessionID:     sessionID,
		Title:         "Exploit candidate for " + match.CVEID,
		Description:   match.Description,
		Narrative:     "A high-severity CVE with exploit availability was correlated to " + subject + ".",
		OWASPCategory: "A06:2021 Vulnerable and Outdated Components",
		Severity:      severityForScore(match.CVSSv3Score),
		Confidence:    match.ConfidenceScore,
		Steps: []models.AttackStep{{
			Order:         1,
			Description:   "Manually confirm " + match.CVEID + " against the affected component and version.",
			ToolSuggested: "nuclei -id " + strings.ToLower(match.CVEID),
		}},
		CreatedAt: time.Now().UTC(),
	}
}

func severityForScore(score float64) models.Severity {
	switch {
	case score >= 9:
		return models.SeverityCritical
	case score >= 7:
		return models.SeverityHigh
	case score >= 4:
		return models.SeverityMedium
	default:
		return models.SeverityLow
	}
}

func CVEIDs(text string) []string {
	matches := cvePattern.FindAllString(strings.ToUpper(text), -1)
	seen := map[string]bool{}
	var out []string
	for _, match := range matches {
		if !seen[match] {
			out = append(out, match)
			seen[match] = true
		}
	}
	return out
}

func dedupeAdvisories(advisories []Advisory) []Advisory {
	seen := map[string]bool{}
	var out []Advisory
	for _, advisory := range advisories {
		if advisory.CVEID == "" || seen[advisory.CVEID] {
			continue
		}
		seen[advisory.CVEID] = true
		out = append(out, advisory)
	}
	return out
}

func normalizeProduct(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "wordpress plugin: ")
	value = strings.TrimPrefix(value, "wordpress theme: ")
	return strings.NewReplacer("-", "", "_", "", " ", "").Replace(value)
}

func versionInRange(version, affected string) bool {
	affected = strings.TrimSpace(affected)
	if strings.Contains(affected, "<=") {
		parts := strings.Split(affected, "<=")
		return compareVersion(version, strings.TrimSpace(parts[len(parts)-1])) <= 0
	}
	if strings.HasPrefix(affected, "<") {
		return compareVersion(version, strings.TrimSpace(strings.TrimPrefix(affected, "<"))) < 0
	}
	return strings.Contains(affected, version)
}

func compareVersion(left, right string) int {
	leftParts := strings.Split(left, ".")
	rightParts := strings.Split(right, ".")
	for i := 0; i < max(len(leftParts), len(rightParts)); i++ {
		lv := partInt(leftParts, i)
		rv := partInt(rightParts, i)
		if lv < rv {
			return -1
		}
		if lv > rv {
			return 1
		}
	}
	return 0
}

func partInt(parts []string, index int) int {
	if index >= len(parts) {
		return 0
	}
	n := 0
	for _, ch := range parts[index] {
		if ch < '0' || ch > '9' {
			break
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

type Cache struct {
	ttl     time.Duration
	now     func() time.Time
	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	advisories []Advisory
	expiresAt  time.Time
}

func NewCache(ttl time.Duration) *Cache {
	return &Cache{ttl: ttl, now: time.Now, entries: map[string]cacheEntry{}}
}

func (c *Cache) Get(key string) ([]Advisory, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || c.now().After(entry.expiresAt) {
		return nil, false
	}
	return append([]Advisory(nil), entry.advisories...), true
}

func (c *Cache) Set(key string, advisories []Advisory) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{advisories: append([]Advisory(nil), advisories...), expiresAt: c.now().Add(c.ttl)}
}

type OfflineSource struct {
	path string
	once sync.Once
	data []Advisory
	err  error
}

func NewOfflineSource(path string) *OfflineSource { return &OfflineSource{path: path} }
func (s *OfflineSource) Name() string             { return "offline" }
func (s *OfflineSource) Search(ctx context.Context, product, version string) ([]Advisory, error) {
	s.once.Do(func() {
		body, err := os.ReadFile(s.path)
		if err != nil {
			s.err = err
			return
		}
		s.err = json.Unmarshal(body, &s.data)
	})
	if s.err != nil {
		return nil, s.err
	}
	return filterAdvisories(s.data, product, version), ctx.Err()
}

type EmbeddedSource struct{}

func (EmbeddedSource) Name() string { return "embedded" }
func (EmbeddedSource) Search(ctx context.Context, product, version string) ([]Advisory, error) {
	return filterAdvisories(embeddedAdvisories, product, version), ctx.Err()
}

func filterAdvisories(advisories []Advisory, product, version string) []Advisory {
	var out []Advisory
	for _, advisory := range advisories {
		if confidenceFor(product, version, advisory) > 0 {
			out = append(out, advisory)
		}
	}
	return out
}

var embeddedAdvisories = []Advisory{
	{
		CVEID:            "CVE-2021-41773",
		Product:          "apache",
		AffectedVersion:  "<=2.4.49",
		FixedVersion:     "2.4.50",
		CVSSv3Score:      7.5,
		Description:      "Apache HTTP Server path traversal and file disclosure vulnerability.",
		PatchAvailable:   true,
		ExploitAvailable: true,
		References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
		Source:           "embedded",
	},
	{
		CVEID:            "CVE-2021-44228",
		Product:          "log4j",
		AffectedVersion:  "<=2.14.1",
		FixedVersion:     "2.17.1",
		CVSSv3Score:      10,
		Description:      "Apache Log4j remote code execution vulnerability.",
		PatchAvailable:   true,
		ExploitAvailable: true,
		References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
		Source:           "embedded",
	},
}
