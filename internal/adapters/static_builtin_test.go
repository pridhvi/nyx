package adapters

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pridhvi/nyx/internal/models"
)

func TestParseStaticOutputToolSpecificFindings(t *testing.T) {
	input := StaticAdapterInput{SessionID: "session-1"}
	cases := []struct {
		tool string
		raw  string
		want string
	}{
		{"semgrep", `{"results":[{"path":"app.py","check_id":"python.sql","start":{"line":7},"extra":{"message":"SQL injection","severity":"ERROR"}}]}`, "app.py"},
		{"bandit", `{"results":[{"filename":"app.py","line_number":3,"issue_text":"hardcoded password","issue_severity":"HIGH"}]}`, "app.py"},
		{"gosec", `{"Issues":[{"file":"main.go","line":"9","details":"G401 weak crypto","severity":"MEDIUM"}]}`, "main.go"},
		{"brakeman", `{"warnings":[{"file":"app/controllers/users_controller.rb","line":12,"message":"SQL Injection","confidence":1}]}`, "users_controller.rb"},
		{"psalm", `[{"file_path":"src/App.php","line_from":4,"message":"Tainted input","severity":"error"}]`, "src/App.php"},
		{"trufflehog", `{"DetectorName":"AWS","SourceMetadata":{"Data":{"Filesystem":{"file":"secrets.txt"}}},"StartLine":2}`, "secrets.txt"},
		{"gitleaks", `[{"RuleID":"generic-api-key","File":"config.js","StartLine":2}]`, "config.js"},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			findings, _ := parseStaticOutput(input, tc.tool, tc.raw)
			if len(findings) == 0 {
				t.Fatalf("expected finding for %s", tc.tool)
			}
			if !strings.Contains(findings[0].URL, tc.want) || !strings.HasPrefix(findings[0].ToolID, "audit/") {
				t.Fatalf("unexpected finding: %#v", findings[0])
			}
		})
	}
}

func TestParseStaticOutputDependencyCVEs(t *testing.T) {
	input := StaticAdapterInput{SessionID: "session-1"}
	cases := []struct {
		tool    string
		raw     string
		pkg     string
		version string
	}{
		{"npm-audit", `{"vulnerabilities":{"lodash":{"range":"<4.17.21","via":[{"source":"CVE-2021-23337","title":"Command Injection"}]}}}`, "lodash", "<4.17.21"},
		{"grype", `{"matches":[{"vulnerability":{"id":"CVE-2024-0001","description":"demo","cvss":[{"baseScore":9.8}],"fix":{"versions":["1.2.3"]}},"artifact":{"name":"openssl","version":"1.0.0"}}]}`, "openssl", "1.0.0"},
		{"safety", `[{"vulnerability_id":"CVE-2023-1234","package":"django","installed_version":"3.0","advisory":"demo"}]`, "django", "3.0"},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			_, cves := parseStaticOutput(input, tc.tool, tc.raw)
			if len(cves) == 0 {
				t.Fatalf("expected cve for %s", tc.tool)
			}
			if cves[0].SessionID != input.SessionID || cves[0].PackageName != tc.pkg || cves[0].PackageVersion != tc.version || cves[0].Source != "audit/"+tc.tool {
				t.Fatalf("unexpected cve: %#v", cves[0])
			}
		})
	}
}

func TestSourceFindingToAuditFindingUsesAuditToolID(t *testing.T) {
	finding := sourceFindingToAuditFinding("s1", "authmiddleware", models.SeverityMedium, models.SourceFinding{
		Kind:       models.SourceKindUnprotectedRoute,
		FilePath:   "app.py",
		LineNumber: 10,
		Value:      "/admin",
	})
	if finding.ToolID != "audit/authmiddleware" || !strings.Contains(finding.URL, "app.py") {
		t.Fatalf("unexpected audit finding: %#v", finding)
	}
}

func TestJavaPatternStaticAdapterCoversBenchmarkClasses(t *testing.T) {
	repo := t.TempDir()
	source := `package demo;
class Demo {
  void test(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws Exception {
    String param = request.getParameter("q");
    String sql = "select * from users where name='" + param + "'";
    statement.executeQuery(sql);
    new ProcessBuilder(param).start();
    response.getWriter().println(param);
    new java.io.FileInputStream(new java.io.File(param));
    javax.crypto.Cipher.getInstance(param);
    java.security.MessageDigest.getInstance(param);
    float r = new java.util.Random().nextFloat();
    javax.servlet.http.Cookie c = new javax.servlet.http.Cookie("sid", param);
    request.getSession().setAttribute("name", param);
    javax.naming.directory.DirContext ctx = null;
    ctx.search("ou=people", param, null);
    javax.xml.xpath.XPath xp = null;
    xp.evaluate(param, document);
    java.io.ObjectInputStream ois = new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(param.getBytes()));
    ois.readObject();
    javax.xml.stream.XMLInputFactory.newInstance();
    new java.net.URL(param).openStream();
    http.csrf(csrf -> csrf.disable());
    org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance();
    return failed(this).output(param).build();
  }
}`
	if err := os.WriteFile(filepath.Join(repo, "Demo.java"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "pom.xml"), []byte(`<project><dependencies><dependency><groupId>com.thoughtworks.xstream</groupId><artifactId>xstream</artifactId><version>1.4.5</version></dependency></dependencies></project>`), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := scanJavaPatternFindings(context.Background(), StaticAdapterInput{SessionID: "session-1", RepoPath: repo})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, finding := range findings {
		if len(finding.Tags) > 0 {
			got[finding.Tags[len(finding.Tags)-1]] = true
		}
	}
	for _, want := range []string{"cmdi", "crypto", "deser", "hash", "ldapi", "nooppass", "outputinj", "pathtraver", "securecookie", "springcsrf", "sqli", "ssrf", "trustbound", "vulndep", "weakrand", "xpathi", "xss", "xxe"} {
		if !got[want] {
			t.Fatalf("missing Java pattern class %s from findings %#v", want, findings)
		}
	}
}
