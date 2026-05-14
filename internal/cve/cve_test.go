package cve

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kanini/nox/internal/models"
)

type countingSource struct {
	calls int
	data  []Advisory
}

func (s *countingSource) Name() string { return "counting" }
func (s *countingSource) Search(context.Context, string, string) ([]Advisory, error) {
	s.calls++
	return s.data, nil
}

func TestCorrelatorCachesSourceResults(t *testing.T) {
	source := &countingSource{data: []Advisory{{
		CVEID:           "CVE-2024-0001",
		Product:         "nginx",
		AffectedVersion: "1.25.0",
		CVSSv3Score:     7.5,
		Source:          "test",
	}}}
	correlator := NewCorrelator([]Source{source}, NewCache(time.Hour))
	session := models.Session{ID: "session-1"}
	targets := []models.Target{{ID: "target-1", Technologies: []models.Technology{{
		ID:       "tech-1",
		TargetID: "target-1",
		Name:     "nginx",
		Version:  "1.25.0",
	}}}}
	if _, err := correlator.Correlate(context.Background(), session, targets, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := correlator.Correlate(context.Background(), session, targets, nil); err != nil {
		t.Fatal(err)
	}
	if source.calls != 1 {
		t.Fatalf("expected one source call due to cache, got %d", source.calls)
	}
}

func TestOfflineSourceMatchesLocalData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cves.json")
	body := `[{"cve_id":"CVE-2024-0002","product":"wordpress","affected_version":"6.4.2","fixed_version":"6.4.3","cvss_v3_score":8.1,"source":"offline"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	source := NewOfflineSource(path)
	advisories, err := source.Search(context.Background(), "WordPress", "6.4.2")
	if err != nil {
		t.Fatal(err)
	}
	if len(advisories) != 1 || advisories[0].CVEID != "CVE-2024-0002" {
		t.Fatalf("unexpected advisories: %#v", advisories)
	}
}

func TestCorrelatorCreatesMatchesAndVectors(t *testing.T) {
	source := &countingSource{data: []Advisory{{
		CVEID:            "CVE-2021-44228",
		Product:          "log4j",
		AffectedVersion:  "<=2.14.1",
		FixedVersion:     "2.17.1",
		CVSSv3Score:      10,
		Description:      "Log4Shell",
		ExploitAvailable: true,
		PatchAvailable:   true,
		Source:           "test",
	}}}
	correlator := NewCorrelator([]Source{source}, NewCache(time.Hour))
	session := models.Session{ID: "session-1"}
	targets := []models.Target{{ID: "target-1", Technologies: []models.Technology{{
		ID:       "tech-1",
		TargetID: "target-1",
		Name:     "log4j",
		Version:  "2.14.1",
	}}}}
	findings := []models.Finding{{
		ID:                 "finding-1",
		EvidenceNormalized: `{"cve":"CVE-2024-12345"}`,
	}}
	result, err := correlator.Correlate(context.Background(), session, targets, findings)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Matches) != 2 {
		t.Fatalf("expected 2 matches, got %#v", result.Matches)
	}
	if result.Matches[0].CVEID != "CVE-2021-44228" || result.Matches[0].TechnologyID != "tech-1" {
		t.Fatalf("expected technology CVE match, got %#v", result.Matches[0])
	}
	if len(result.Vectors) != 1 || result.Vectors[0].Severity != models.SeverityCritical {
		t.Fatalf("expected critical draft vector, got %#v", result.Vectors)
	}
}

func TestCVEIDsDeduplicate(t *testing.T) {
	ids := CVEIDs("CVE-2024-0001 cve-2024-0001 CVE-2023-12345")
	if len(ids) != 2 || ids[0] != "CVE-2024-0001" || ids[1] != "CVE-2023-12345" {
		t.Fatalf("unexpected ids: %#v", ids)
	}
}
