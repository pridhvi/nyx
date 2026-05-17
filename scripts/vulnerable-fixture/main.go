package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

var api_key = "AKIAIOSFODNN7EXAMPLE"
var db fakeDB
var weakSessionCounter int

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<html><head><title>Nox vulnerable fixture</title></head><body><a href="/admin">admin</a><a href="/upload">upload</a><script src="/static/app.js"></script></body></html>`)
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, "default admin portal")
	})
	mux.HandleFunc("/api/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		q := r.URL.Query().Get("q")
		_, _ = db.Query("SELECT * FROM users WHERE name = '" + q + "'")
		switch {
		case strings.Contains(q, "'1'='1") || strings.Contains(q, "1=1"):
			fmt.Fprintln(w, `{"result":"fixture-user"}`)
			return
		case strings.Contains(q, "'1'='2") || strings.Contains(q, "1=2"):
			fmt.Fprintln(w, `{"result":"no rows"}`)
			return
		case strings.Contains(q, "'"):
			fmt.Fprintln(w, `You have an error in your SQL syntax near "'"`)
			return
		}
		fmt.Fprintf(w, `{"query":%q,"warning":"unsanitized reflected parameter"}`, q)
	})
	mux.HandleFunc("/api/basket", func(w http.ResponseWriter, r *http.Request) {
		id := first(r.URL.Query().Get("id"), "1")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"basket_id":%q,"owner":"fixture-user-%s","items":["juice","cookie"]}`, id, id)
	})
	mux.HandleFunc("/coupon", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<form method="get" action="/coupon/apply"><input name="coupon"><input name="cart_id" value="1"><input name="discount" value="25"><button>apply</button></form>`)
	})
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"types":[{"name":"Query"}]}}}`)
	})
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"openapi":"3.0.3","info":{"title":"Nox vulnerable fixture","version":"1.0.0"},"paths":{"/api/search":{"get":{"parameters":[{"name":"q","in":"query","schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},"/upload":{"post":{"responses":{"200":{"description":"ok"}}}}}}`)
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseMultipartForm(1 << 20)
		if r.MultipartForm != nil {
			for _, headers := range r.MultipartForm.File {
				for _, header := range headers {
					file, err := header.Open()
					if err != nil {
						continue
					}
					body, _ := io.ReadAll(io.LimitReader(file, 4096))
					_ = file.Close()
					fmt.Fprintf(w, "uploaded %s\n%s", header.Filename, string(body))
					return
				}
			}
			fmt.Fprintf(w, "received %d files", len(r.MultipartForm.File))
			return
		}
		fmt.Fprintln(w, `<form method="post" enctype="multipart/form-data"><input type="file" name="file"><button>upload</button></form>`)
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target != "" {
			_, _ = http.Get(target)
		}
		http.Redirect(w, r, first(target, "/"), http.StatusFound)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprintln(w, `<form method="post"><input name="username"><input name="password" type="password"><button>login</button></form>`)
			return
		}
		_ = r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")
		if username == "locked" {
			w.WriteHeader(http.StatusLocked)
			fmt.Fprintln(w, "account locked after too many attempts")
			return
		}
		if username == "admin" && password == "password" {
			fmt.Fprintln(w, "success welcome dashboard token=fixture-token")
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "invalid credentials")
	})
	mux.HandleFunc("/csrf", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `<form method="get" action="/csrf/change"><input name="password_new"><input name="password_conf"><button name="Change" value="Change">Change</button></form>`)
	})
	mux.HandleFunc("/weak-session", func(w http.ResponseWriter, r *http.Request) {
		weakSessionCounter++
		http.SetCookie(w, &http.Cookie{Name: "weakSessionID", Value: fmt.Sprintf("%d", weakSessionCounter), Path: "/"})
		fmt.Fprintf(w, "Session ID: %d", weakSessionCounter)
	})
	mux.HandleFunc("/ssti", func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("q")
		if value == "{{7*7}}" || value == "${7*7}" {
			fmt.Fprintln(w, "49")
			return
		}
		fmt.Fprintf(w, "template preview: %s", value)
	})
	mux.HandleFunc("/xxe", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		text := string(body)
		if strings.Contains(text, `<!ENTITY nox "`) {
			start := strings.Index(text, `<!ENTITY nox "`) + len(`<!ENTITY nox "`)
			rest := text[start:]
			end := strings.Index(rest, `"`)
			if end > 0 {
				_, _ = fmt.Fprintln(w, "resolved "+rest[:end])
				return
			}
		}
		_, _ = fmt.Fprintln(w, "xml parser accepted fixture-safe marker")
	})
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, `const apiKey = %q; fetch("/api/search?q=test"); fetch("/graphql", {method: "POST"});`, api_key)
	})
	addr := first(os.Getenv("NOX_FIXTURE_ADDR"), "127.0.0.1:18081")
	fmt.Println("fixture listening on http://" + addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func first(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

type fakeDB struct{}

func (fakeDB) Query(string) (int, error) {
	return 0, nil
}
