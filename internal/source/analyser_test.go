package source

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pridhvi/nyx/internal/models"
)

func TestAnalyseExtractsSupportedLanguagesWithoutExecutingCode(t *testing.T) {
	cases := []struct {
		name     string
		file     string
		body     string
		language string
		kinds    []models.SourceFindingKind
	}{
		{
			name:     "python",
			file:     "app.py",
			language: "python",
			body:     "@app.get(\"/users\")\ndef users():\n    q = request.args.get(\"q\")\n    db.session.execute(\"SELECT * FROM users WHERE name=\" + q)\n    requests.get(q)\n",
			kinds:    []models.SourceFindingKind{models.SourceKindRoute, models.SourceKindParameter, models.SourceKindSQLSink, models.SourceKindSSRFSink},
		},
		{
			name:     "javascript",
			file:     "app.js",
			language: "javascript",
			body:     "app.post('/upload', upload.single('file'), (req, res) => { const id = req.query.id; fetch(id); const api_key = 'secret'; })\n",
			kinds:    []models.SourceFindingKind{models.SourceKindRoute, models.SourceKindParameter, models.SourceKindFileUpload, models.SourceKindSSRFSink, models.SourceKindSecret},
		},
		{
			name:     "go",
			file:     "main.go",
			language: "go",
			body:     "func main() { http.HandleFunc(\"/admin\", handler); q := r.URL.Query().Get(\"q\"); http.Get(q) }\n",
			kinds:    []models.SourceFindingKind{models.SourceKindRoute, models.SourceKindParameter, models.SourceKindSSRFSink},
		},
		{
			name:     "php",
			file:     "routes.php",
			language: "php",
			body:     "Route::get('/account', function () { $id = $_GET['id']; unserialize($id); move_uploaded_file($_FILES['f']['tmp_name'], '/tmp/f'); });\n",
			kinds:    []models.SourceFindingKind{models.SourceKindRoute, models.SourceKindParameter, models.SourceKindDeserialisationSink, models.SourceKindFileUpload},
		},
		{
			name:     "ruby",
			file:     "app.rb",
			language: "ruby",
			body:     "get '/orders' do\n  id = params[:id]\n  Net::HTTP.get(URI(id))\nend\n",
			kinds:    []models.SourceFindingKind{models.SourceKindRoute, models.SourceKindParameter, models.SourceKindSSRFSink},
		},
		{
			name:     "java",
			file:     "App.java",
			language: "java",
			body:     "@GetMapping(\"/api\")\nString api(@RequestParam(\"id\") String id) { new ObjectInputStream(in).readObject(); return id; }\n",
			kinds:    []models.SourceFindingKind{models.SourceKindRoute, models.SourceKindParameter, models.SourceKindDeserialisationSink},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, "tests"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "tests", tc.file), []byte("password = \"ignored\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			result, err := Analyse(dir, "session-1")
			if err != nil {
				t.Fatal(err)
			}
			if result.Language != tc.language {
				t.Fatalf("expected language %s, got %s", tc.language, result.Language)
			}
			got := map[models.SourceFindingKind]bool{}
			for _, finding := range result.Findings {
				got[finding.Kind] = true
				if filepath.ToSlash(finding.FilePath) == filepath.ToSlash(filepath.Join("tests", tc.file)) {
					t.Fatalf("expected test fixture file to be excluded, got %#v", finding)
				}
			}
			for _, kind := range tc.kinds {
				if !got[kind] {
					t.Fatalf("expected kind %s in %#v", kind, result.Findings)
				}
			}
		})
	}
}

func TestAnalyseSkipsSymlinkedFiles(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("func main() { http.HandleFunc(\"/ok\", handler) }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.go"), []byte("var api_key = \"outside\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.go"), filepath.Join(dir, "linked_secret.go")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	result, err := Analyse(dir, "session-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range result.Findings {
		if filepath.ToSlash(finding.FilePath) == "linked_secret.go" || finding.Value == "var api_key = \"outside\"" {
			t.Fatalf("expected symlinked file to be skipped, got %#v", finding)
		}
	}
}

func TestReadSourceFileInRootRejectsSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.go"), []byte("var api_key = \"outside\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.go"), filepath.Join(dir, "linked_secret.go")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if body, err := readSourceFileInRoot(root, "linked_secret.go"); err == nil {
		t.Fatalf("expected root-confined read to reject symlink escape, got %q", string(body))
	}
}
