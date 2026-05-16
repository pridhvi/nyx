package main

import (
	"fmt"
	"net/http"
	"os"
)

var api_key = "AKIAIOSFODNN7EXAMPLE"
var db fakeDB

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
		fmt.Fprintf(w, `{"query":%q,"warning":"unsanitized reflected parameter"}`, q)
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
