package burp

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/models"
)

func TestImportXMLPersistsTargetFindingAndEvidence(t *testing.T) {
	ctx := context.Background()
	store, session := burpTestStore(t)
	defer store.Close()
	request := base64.StdEncoding.EncodeToString([]byte("GET /admin HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	response := base64.StdEncoding.EncodeToString([]byte("HTTP/1.1 200 OK\r\n\r\nadmin"))
	raw := []byte(`<issues><issue><host>https://example.test</host><path>/admin</path><location>https://example.test/admin</location><name>Exposed admin panel</name><severity>High</severity><confidence>Firm</confidence><requestresponse><request>` + request + `</request><response>` + response + `</response></requestresponse></issue></issues>`)

	result, err := ImportXML(ctx, store, session, raw)
	if err != nil {
		t.Fatal(err)
	}
	if result.TargetsImported != 1 || result.FindingsImported != 1 || result.EvidenceImported != 1 {
		t.Fatalf("unexpected import result: %#v", result)
	}
	findings, err := store.ListFindings(ctx, session.ID, db.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %#v", findings)
	}
	if findings[0].ToolID != "burp" || findings[0].Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if findings[0].HTTPEvidence == nil || !strings.Contains(findings[0].HTTPEvidence.RequestRaw, "GET /admin") {
		t.Fatalf("expected decoded HTTP evidence, got %#v", findings[0].HTTPEvidence)
	}
}

func TestExportScopeAndFindingsUsePersistedData(t *testing.T) {
	ctx := context.Background()
	store, session := burpTestStore(t)
	defer store.Close()
	target := models.Target{ID: models.NewID(), SessionID: session.ID, Host: "api.example.test", Port: 443, Protocol: "https", IsAlive: true, CreatedAt: time.Now().UTC()}
	if err := store.InsertTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	finding := models.Finding{ID: models.NewID(), SessionID: session.ID, TargetID: target.ID, ToolID: "test", Type: models.FindingTypeVulnerability, Severity: models.SeverityMedium, Title: "Reflected input", URL: "https://api.example.test/search?q=x", CreatedAt: time.Now().UTC()}
	if err := store.InsertFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	scope, err := ExportScope(ctx, store, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(scope), "https://api.example.test:443") {
		t.Fatalf("expected target in scope export, got %s", string(scope))
	}
	exported, err := ExportFindings(ctx, store, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(exported), "Reflected input") || !strings.Contains(string(exported), "https://api.example.test/search") {
		t.Fatalf("expected finding in export, got %s", string(exported))
	}
}

func burpTestStore(t *testing.T) (*db.Store, models.Session) {
	t.Helper()
	ctx := context.Background()
	session := models.Session{ID: models.NewID(), Status: models.SessionStatusCompleted, Mode: models.ScanModeActive, TargetInput: "https://example.test", InScope: []string{"https://example.test"}, CreatedAt: time.Now().UTC()}
	target := models.Target{ID: models.NewID(), SessionID: session.ID, Host: "seed.example.test", Port: 443, Protocol: "https", IsAlive: true, CreatedAt: time.Now().UTC()}
	dir := t.TempDir()
	if _, err := db.CreateSessionDB(ctx, dir, session, target); err != nil {
		t.Fatal(err)
	}
	store, err := db.OpenSession(ctx, dir, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	return store, session
}
