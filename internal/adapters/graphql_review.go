package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/models"
)

type GraphQLSecurityReview struct{}

func NewGraphQLSecurityReview() GraphQLSecurityReview { return GraphQLSecurityReview{} }
func (GraphQLSecurityReview) ID() string              { return "graphql-security-review" }
func (GraphQLSecurityReview) Name() string            { return "GraphQL Security Review" }
func (GraphQLSecurityReview) Phase() Phase            { return PhaseVulnScan }
func (GraphQLSecurityReview) DependsOn() []string     { return []string{"graphql-introspection"} }
func (GraphQLSecurityReview) ShouldRun(input AdapterInput) bool {
	return activeOnly(input) && liveHTTP(input)
}

func (a GraphQLSecurityReview) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	endpoint := joinTargetPath(input.Target, "/graphql")
	args := []string{endpoint}
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	client := input.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	evidence := graphqlReviewEvidence{Endpoint: endpoint}
	typenameBody, typenameStatus, typenameErr := graphqlJSONPost(ctx, input, client, endpoint, map[string]any{"query": "query NyxTypename { __typename }"}, nil)
	evidence.TypenameStatus = typenameStatus
	evidence.TypenameBody = typenameBody
	if typenameErr != nil {
		run.RawStderr = typenameErr.Error()
		run.ExitCode = 1
		run.DurationMS = time.Since(run.StartedAt).Milliseconds()
		return AdapterOutput{ToolRun: run}, nil
	}
	schemaBody, schemaStatus, _ := graphqlJSONPost(ctx, input, client, endpoint, map[string]any{"query": graphqlReviewIntrospectionQuery}, nil)
	evidence.SchemaStatus = schemaStatus
	evidence.SchemaBody = schemaBody
	evidence.Schema = parseGraphQLReviewSchema(schemaBody)
	suggestionBody, suggestionStatus, _ := graphqlJSONPost(ctx, input, client, endpoint, map[string]any{"query": "query NyxFieldSuggestion { system }"}, nil)
	evidence.SuggestionStatus = suggestionStatus
	evidence.SuggestionBody = suggestionBody
	batchBody, batchStatus, _ := graphqlJSONPost(ctx, input, client, endpoint, []map[string]any{
		{"query": "query NyxBatchOne { __typename }"},
		{"query": "query NyxBatchTwo { __typename }"},
	}, nil)
	evidence.BatchStatus = batchStatus
	evidence.BatchBody = batchBody
	aliasBody, aliasStatus, _ := graphqlJSONPost(ctx, input, client, endpoint, map[string]any{"query": "query NyxAliasCheck { a: __typename b: __typename }"}, nil)
	evidence.AliasStatus = aliasStatus
	evidence.AliasBody = aliasBody
	duplicateBody, duplicateStatus, _ := graphqlJSONPost(ctx, input, client, endpoint, map[string]any{"query": "query NyxDuplicateField { __typename __typename }"}, nil)
	evidence.DuplicateStatus = duplicateStatus
	evidence.DuplicateBody = duplicateBody
	graphiqlEndpoint := joinTargetPath(input.Target, "/graphiql")
	graphiqlHeaders := map[string]string{"Cookie": "env=graphiql:enable"}
	graphiqlBody, graphiqlStatus, _ := graphqlJSONPost(ctx, input, client, graphiqlEndpoint, map[string]any{"query": "query NyxGraphiQLStackTrace { notARealField }"}, graphiqlHeaders)
	evidence.GraphiQLStatus = graphiqlStatus
	evidence.GraphiQLBody = graphiqlBody

	findings := graphqlSecurityReviewFindings(input, evidence)
	run.RawStdout = evidence.summary()
	run.ExitCode = 0
	run.FindingCount = len(findings)
	run.DurationMS = time.Since(run.StartedAt).Milliseconds()
	now := time.Now().UTC()
	run.NormalizedAt = &now
	return AdapterOutput{Findings: findings, ToolRun: run}, nil
}

func graphqlJSONPost(ctx context.Context, input AdapterInput, client HTTPDoer, endpoint string, payload any, headers map[string]string) (string, int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", 0, err
	}
	req, err := newHTTPRequestWithAuth(ctx, input, http.MethodPost, endpoint, bytes.NewReader(body), "nyx/0.1 graphql-security-review")
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return string(respBody), resp.StatusCode, nil
}

type graphqlReviewEvidence struct {
	Endpoint         string
	TypenameStatus   int
	TypenameBody     string
	SchemaStatus     int
	SchemaBody       string
	Schema           graphqlReviewSchema
	SuggestionStatus int
	SuggestionBody   string
	BatchStatus      int
	BatchBody        string
	AliasStatus      int
	AliasBody        string
	DuplicateStatus  int
	DuplicateBody    string
	GraphiQLStatus   int
	GraphiQLBody     string
}

func (e graphqlReviewEvidence) summary() string {
	return strings.Join([]string{
		fmt.Sprintf("endpoint=%s", e.Endpoint),
		fmt.Sprintf("typename_status=%d", e.TypenameStatus),
		fmt.Sprintf("schema_status=%d", e.SchemaStatus),
		fmt.Sprintf("suggestion_status=%d", e.SuggestionStatus),
		fmt.Sprintf("batch_status=%d", e.BatchStatus),
		fmt.Sprintf("alias_status=%d", e.AliasStatus),
		fmt.Sprintf("duplicate_status=%d", e.DuplicateStatus),
		fmt.Sprintf("graphiql_status=%d", e.GraphiQLStatus),
		fmt.Sprintf("query_fields=%s", strings.Join(e.Schema.fieldNames("Query"), ",")),
		fmt.Sprintf("mutation_fields=%s", strings.Join(e.Schema.fieldNames("Mutation"), ",")),
	}, "\n")
}

type graphqlReviewSchema struct {
	Fields []graphqlReviewField
}

type graphqlReviewField struct {
	Parent string
	Name   string
	Args   []string
	Type   string
}

func parseGraphQLReviewSchema(raw string) graphqlReviewSchema {
	var body struct {
		Data struct {
			Schema struct {
				QueryType    graphQLTypeRef `json:"queryType"`
				MutationType graphQLTypeRef `json:"mutationType"`
				Types        []struct {
					Name   string `json:"name"`
					Kind   string `json:"kind"`
					Fields []struct {
						Name string `json:"name"`
						Args []struct {
							Name string `json:"name"`
						} `json:"args"`
						Type graphQLTypeRef `json:"type"`
					} `json:"fields"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		return graphqlReviewSchema{}
	}
	queryName := firstNonEmpty(body.Data.Schema.QueryType.Name, "Query")
	mutationName := firstNonEmpty(body.Data.Schema.MutationType.Name, "Mutation")
	var schema graphqlReviewSchema
	for _, typ := range body.Data.Schema.Types {
		if typ.Name == "" || len(typ.Fields) == 0 || strings.HasPrefix(typ.Name, "__") {
			continue
		}
		parent := typ.Name
		if typ.Name == queryName {
			parent = "Query"
		}
		if typ.Name == mutationName {
			parent = "Mutation"
		}
		for _, field := range typ.Fields {
			args := make([]string, 0, len(field.Args))
			for _, arg := range field.Args {
				args = append(args, arg.Name)
			}
			schema.Fields = append(schema.Fields, graphqlReviewField{
				Parent: parent,
				Name:   field.Name,
				Args:   args,
				Type:   field.Type.name(),
			})
		}
	}
	return schema
}

type graphQLTypeRef struct {
	Kind   string          `json:"kind"`
	Name   string          `json:"name"`
	OfType *graphQLTypeRef `json:"ofType"`
}

func (r graphQLTypeRef) name() string {
	if r.Name != "" {
		return r.Name
	}
	if r.OfType != nil {
		return r.OfType.name()
	}
	return ""
}

func (s graphqlReviewSchema) hasField(parent, name string) bool {
	for _, field := range s.Fields {
		if strings.EqualFold(field.Parent, parent) && strings.EqualFold(field.Name, name) {
			return true
		}
	}
	return false
}

func (s graphqlReviewSchema) hasFieldWithArgs(parent, name string, args ...string) bool {
	for _, field := range s.Fields {
		if !strings.EqualFold(field.Parent, parent) || !strings.EqualFold(field.Name, name) {
			continue
		}
		if hasArgs(field.Args, args...) {
			return true
		}
	}
	return false
}

func (s graphqlReviewSchema) fieldNames(parent string) []string {
	var names []string
	for _, field := range s.Fields {
		if strings.EqualFold(field.Parent, parent) {
			names = append(names, field.Name)
		}
	}
	return names
}

func (s graphqlReviewSchema) hasRecursiveObjectCycle() bool {
	edges := map[string][]string{}
	for _, field := range s.Fields {
		if field.Parent == "" || field.Type == "" || field.Parent == "Query" || field.Parent == "Mutation" {
			continue
		}
		edges[field.Parent] = append(edges[field.Parent], field.Type)
	}
	for start := range edges {
		if graphQLHasCycleFrom(start, start, edges, map[string]bool{}, 0) {
			return true
		}
	}
	return false
}

func graphQLHasCycleFrom(start, current string, edges map[string][]string, visited map[string]bool, depth int) bool {
	if depth > 0 && current == start {
		return true
	}
	if depth > 8 || visited[current] {
		return false
	}
	visited[current] = true
	for _, next := range edges[current] {
		if graphQLHasCycleFrom(start, next, edges, cloneBoolMap(visited), depth+1) {
			return true
		}
	}
	return false
}

func cloneBoolMap(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func hasArgs(actual []string, expected ...string) bool {
	set := map[string]bool{}
	for _, arg := range actual {
		set[strings.ToLower(arg)] = true
	}
	for _, arg := range expected {
		if !set[strings.ToLower(arg)] {
			return false
		}
	}
	return true
}

func graphqlSecurityReviewFindings(input AdapterInput, evidence graphqlReviewEvidence) []models.Finding {
	schema := evidence.Schema
	var out []models.Finding
	add := func(category string, findingType models.FindingType, severity models.Severity, confidence float64, title, description, remediation, proof string, tags ...string) {
		out = append(out, graphqlReviewFinding(input, category, findingType, severity, confidence, title, description, remediation, proof, tags))
	}
	if responseHasData(evidence.TypenameBody) {
		add("recon-detection", models.FindingTypeInfo, models.SeverityInfo, 0.9, "GraphQL endpoint detected", "The target responded to a minimal GraphQL query at a common GraphQL endpoint.", "Confirm GraphQL exposure is intentional and include it in API security review scope.", evidence.TypenameBody, "graphql", "recon")
	}
	if strings.Contains(strings.ToLower(evidence.GraphiQLBody), "graphene") || strings.Contains(strings.ToLower(evidence.GraphiQLBody), "site-packages") {
		add("recon-fingerprinting", models.FindingTypeInfo, models.SeverityInfo, 0.8, "GraphQL implementation fingerprint leaked through errors", "GraphQL error output includes framework or runtime details that help fingerprint the implementation.", "Return generic GraphQL errors in production and avoid stack/runtime details in client responses.", evidence.GraphiQLBody, "graphql", "fingerprint")
	}
	if strings.Contains(evidence.BatchBody, `[`) && strings.Contains(evidence.BatchBody, `"data"`) {
		add("dos-batch", models.FindingTypeMisconfiguration, models.SeverityLow, 0.75, "GraphQL batching is enabled", "The GraphQL endpoint accepted an array of operations. Batching can amplify expensive operations and brute-force attempts when not rate-limited.", "Set bounded batch limits, apply per-operation cost controls, and rate-limit GraphQL requests.", evidence.BatchBody, "graphql", "dos")
	}
	if schema.hasRecursiveObjectCycle() {
		add("dos-recursion", models.FindingTypeMisconfiguration, models.SeverityLow, 0.7, "GraphQL schema contains recursive object relationships", "The schema exposes object fields that can reference back into each other, which may allow deeply nested recursive queries without depth controls.", "Enforce query depth limits and test recursive query paths under production limits.", strings.Join(schema.fieldNames("Query"), ","), "graphql", "dos")
	}
	if schema.hasField("Query", "systemUpdate") || schema.hasField("Query", "systemDiagnostics") || schema.hasField("Query", "systemDebug") || schema.hasField("Query", "systemHealth") {
		add("dos-intensive", models.FindingTypeMisconfiguration, models.SeverityLow, 0.65, "GraphQL exposes operational fields that require cost review", "The schema exposes operational or diagnostic fields that can be expensive or security-sensitive if unauthenticated or repeatedly invoked.", "Assign query cost to expensive fields, cache where safe, and require authorization for operational resolvers.", strings.Join(schema.fieldNames("Query"), ","), "graphql", "dos")
	}
	if responseHasData(evidence.DuplicateBody) {
		add("dos-fielddup", models.FindingTypeMisconfiguration, models.SeverityLow, 0.6, "GraphQL duplicate field handling requires review", "The endpoint accepts duplicate field selections. Repeated expensive fields can increase resolver work if the server does not de-duplicate or cost-limit queries.", "Add field de-duplication, query complexity limits, or resolver-level safeguards for expensive fields.", evidence.DuplicateBody, "graphql", "dos")
	}
	if responseHasData(evidence.AliasBody) {
		add("dos-aliases", models.FindingTypeMisconfiguration, models.SeverityLow, 0.6, "GraphQL aliases are accepted and require cost controls", "The endpoint accepts aliases. Alias-heavy queries can multiply expensive resolver calls if query cost analysis does not account for them.", "Account for aliases in query cost controls and rate-limit expensive resolver paths.", evidence.AliasBody, "graphql", "dos")
	}
	if schema.hasRecursiveObjectCycle() {
		add("dos-circular-fragment", models.FindingTypeMisconfiguration, models.SeverityLow, 0.45, "GraphQL recursive schema should be tested for circular fragment handling", "Recursive object relationships are present, so circular-fragment and fragment-spread validation should be verified manually under production parser settings.", "Ensure the GraphQL parser rejects fragment cycles and enforce depth/complexity limits before resolver execution.", strings.Join(schema.fieldNames("Query"), ","), "graphql", "dos")
	}
	if strings.Contains(evidence.SchemaBody, `"__schema"`) {
		add("info-introspection", models.FindingTypeExposure, models.SeverityMedium, 0.9, "GraphQL introspection is enabled", "The endpoint returned GraphQL schema introspection data, exposing available queries, mutations, arguments, and object relationships.", "Disable introspection in production or restrict schema discovery to authenticated developer roles.", evidence.SchemaBody, "graphql", "introspection")
	}
	if evidence.GraphiQLStatus >= 200 && evidence.GraphiQLStatus < 500 && !strings.Contains(evidence.GraphiQLBody, "GraphiQL Access Rejected") {
		add("info-igql", models.FindingTypeExposure, models.SeverityMedium, 0.85, "GraphiQL endpoint is reachable", "The GraphiQL endpoint accepted a request and returned GraphQL processing output. Browser GraphQL consoles are useful reconnaissance surfaces when exposed.", "Disable GraphiQL in production or require strong authenticated access.", evidence.GraphiQLBody, "graphql", "graphiql")
	}
	if strings.Contains(strings.ToLower(evidence.SuggestionBody), "did you mean") {
		add("info-suggestions", models.FindingTypeExposure, models.SeverityLow, 0.85, "GraphQL field suggestions disclose schema hints", "Invalid field probes returned GraphQL suggestions that reveal nearby field names.", "Disable or reduce field suggestions in production error responses.", evidence.SuggestionBody, "graphql", "suggestions")
	}
	if schema.hasFieldWithArgs("Mutation", "importPaste", "host", "port", "path", "scheme") {
		add("info-ssrf", models.FindingTypeVulnerability, models.SeverityHigh, 0.7, "GraphQL mutation accepts server-side URL components", "A mutation accepts host, port, path, and scheme arguments, which indicates a server-side fetch workflow that requires SSRF review.", "Constrain outbound fetch destinations with allow-lists and egress controls, and reject local/private/metadata-service targets.", "mutation importPaste(host, port, path, scheme)", "graphql", "ssrf")
		add("exec-os-1", models.FindingTypeVulnerability, models.SeverityHigh, 0.65, "GraphQL import workflow requires command-injection review", "A server-side import mutation accepts URL components that may be passed to a fetch command or subprocess in vulnerable implementations.", "Build outbound requests with HTTP client APIs, never shell commands, and validate each URL component before use.", "mutation importPaste(host, port, path, scheme)", "graphql", "command-injection")
	}
	if schema.hasFieldWithArgs("Query", "systemDiagnostics", "username", "password", "cmd") {
		add("exec-os-2", models.FindingTypeVulnerability, models.SeverityHigh, 0.75, "GraphQL diagnostic field accepts command input", "A GraphQL diagnostic query accepts username, password, and command arguments, which is a high-risk administrative command surface.", "Remove command execution from GraphQL resolvers or replace it with fixed, authorized, non-shell diagnostic actions.", "query systemDiagnostics(username, password, cmd)", "graphql", "command-injection")
		add("misc-weakpass", models.FindingTypeVulnerability, models.SeverityMedium, 0.65, "GraphQL diagnostic field uses inline password arguments", "An administrative GraphQL field accepts credentials directly as query arguments, making brute-force and audit-log exposure risks likely without strong controls.", "Move administrative access to normal authenticated sessions, add rate limits, and avoid password arguments in GraphQL queries.", "query systemDiagnostics(username, password, cmd)", "graphql", "authentication")
	}
	if schema.hasFieldWithArgs("Mutation", "createPaste", "title", "content") {
		add("inj-xss", models.FindingTypeVulnerability, models.SeverityHigh, 0.65, "GraphQL content creation requires stored-XSS review", "A mutation accepts user-controlled title/content fields that are later rendered by the application.", "HTML-encode untrusted content on output and sanitize rich text with a strict allow-list when rich content is required.", "mutation createPaste(title, content)", "graphql", "xss")
		add("inj-html", models.FindingTypeVulnerability, models.SeverityMedium, 0.65, "GraphQL content creation requires HTML-injection review", "A mutation accepts user-controlled title/content fields that may render as HTML in downstream views.", "Render user content as text by default and sanitize allowed markup before storage or display.", "mutation createPaste(title, content)", "graphql", "html-injection")
	}
	if schema.hasField("Query", "audits") && len(schema.fieldNames("Mutation")) > 0 {
		add("inj-log", models.FindingTypeVulnerability, models.SeverityLow, 0.6, "GraphQL operation audit log requires spoofing review", "The schema exposes audit data and state-changing mutations. Operation names and query text should be normalized before being logged or displayed.", "Escape log output, record structured metadata, and restrict untrusted operation names in audit views.", "query audits with mutations "+strings.Join(schema.fieldNames("Mutation"), ","), "graphql", "log-injection")
	}
	if schema.hasFieldWithArgs("Query", "pastes", "filter") {
		add("inj-sql", models.FindingTypeVulnerability, models.SeverityHigh, 0.7, "GraphQL filter argument requires SQL injection review", "A list query exposes a free-form filter argument that may be passed to backend query construction.", "Use ORM parameter binding or prepared statements for GraphQL filters; never concatenate filter strings into SQL.", "query pastes(filter)", "graphql", "sqli")
	}
	if schema.hasFieldWithArgs("Query", "me", "token") {
		add("bypassauthz-token", models.FindingTypeVulnerability, models.SeverityHigh, 0.7, "GraphQL identity query accepts caller-supplied token argument", "A GraphQL identity resolver accepts a token as an argument, which requires strict signature, expiry, and authorization validation.", "Validate JWT signatures and claims server-side, and prefer authorization headers over user-controlled GraphQL token arguments.", "query me(token)", "graphql", "authorization", "jwt")
	}
	if evidence.GraphiQLStatus >= 200 && evidence.GraphiQLStatus < 500 && !strings.Contains(evidence.GraphiQLBody, "GraphiQL Access Rejected") {
		add("bypassauthz-igql", models.FindingTypeVulnerability, models.SeverityMedium, 0.75, "GraphiQL access control appears bypassable", "The GraphiQL endpoint processed a request when a client-controlled environment cookie was supplied.", "Do not rely on client-controlled cookies to enable administrative consoles; enforce server-side authorization.", evidence.GraphiQLBody, "graphql", "authorization", "graphiql")
	}
	if schema.hasField("Query", "systemHealth") {
		add("bypassauthz-denylist", models.FindingTypeMisconfiguration, models.SeverityMedium, 0.6, "GraphQL deny-list controls require operation-name bypass review", "A sensitive health/diagnostic field is present. Deny-list based GraphQL protections can often be bypassed with operation names, aliases, or query shape changes.", "Use positive allow-lists for trusted operations or enforce authorization at resolver level.", "query systemHealth", "graphql", "authorization")
	}
	if strings.Contains(strings.ToLower(evidence.GraphiQLBody), "stack") || strings.Contains(strings.ToLower(evidence.GraphiQLBody), "traceback") || strings.Contains(strings.ToLower(evidence.GraphiQLBody), "exception") {
		add("info-stacktrace", models.FindingTypeExposure, models.SeverityMedium, 0.85, "GraphQL error response exposes stack trace details", "The GraphQL error response included debug or stack-trace metadata.", "Disable debug error formatting in production and return generic GraphQL errors to clients.", evidence.GraphiQLBody, "graphql", "stacktrace")
	}
	if schema.hasFieldWithArgs("Mutation", "uploadPaste", "filename", "content") {
		add("misc-filewrite", models.FindingTypeVulnerability, models.SeverityHigh, 0.7, "GraphQL file upload accepts caller-controlled filename", "A mutation accepts filename and content arguments, which requires path traversal and arbitrary file-write validation.", "Store uploads under a fixed root, canonicalize filenames, reject path separators, and generate server-side storage names.", "mutation uploadPaste(filename, content)", "graphql", "path-traversal", "file-write")
	}
	return out
}

func responseHasData(body string) bool {
	return strings.Contains(body, `"data"`) && !strings.Contains(body, `"errors"`)
}

func graphqlReviewFinding(input AdapterInput, category string, findingType models.FindingType, severity models.Severity, confidence float64, title, description, remediation, raw string, tags []string) models.Finding {
	normalized := map[string]any{
		"graphql_review_category": category,
		"category":                category,
	}
	for key, value := range graphqlReviewProofContext(category, raw) {
		normalized[key] = value
	}
	finding := externalFinding(input, "graphql-security-review", findingType, severity, title, description, remediation, limitString(raw, 6000), normalized, append([]string{"graphql-review", category}, tags...))
	finding.Confidence = confidence
	return finding
}

func graphqlReviewProofContext(category, raw string) map[string]any {
	trimmed := strings.TrimSpace(raw)
	context := map[string]any{
		"proof_excerpt":       limitString(trimmed, 600),
		"manual_verification": graphqlReviewManualVerification(category),
	}
	operationType, field, args := parseGraphQLOperationProof(trimmed)
	if operationType != "" {
		context["operation_type"] = operationType
	}
	if field != "" {
		context["field"] = field
	}
	if len(args) > 0 {
		context["arguments"] = args
	}
	return context
}

func parseGraphQLOperationProof(raw string) (string, string, []string) {
	trimmed := strings.TrimSpace(raw)
	operation, rest, ok := strings.Cut(trimmed, " ")
	if !ok {
		return "", "", nil
	}
	operation = strings.ToLower(strings.TrimSpace(operation))
	if operation != "query" && operation != "mutation" {
		return "", "", nil
	}
	rest = strings.TrimSpace(rest)
	field := rest
	if idx := strings.IndexAny(field, " ({"); idx >= 0 {
		field = field[:idx]
	}
	field = strings.TrimSpace(field)
	var args []string
	if start := strings.Index(rest, "("); start >= 0 {
		if end := strings.Index(rest[start+1:], ")"); end >= 0 {
			argList := rest[start+1 : start+1+end]
			for _, arg := range strings.Split(argList, ",") {
				arg = strings.TrimSpace(arg)
				if arg == "" {
					continue
				}
				if before, _, ok := strings.Cut(arg, ":"); ok {
					arg = strings.TrimSpace(before)
				}
				args = append(args, arg)
			}
		}
	}
	return operation, field, args
}

func graphqlReviewManualVerification(category string) string {
	switch {
	case strings.HasPrefix(category, "dos-"):
		return "Review depth, alias, duplicate-field, batch, and resolver cost limits before treating this as exploitable denial of service."
	case strings.HasPrefix(category, "info-") || strings.HasPrefix(category, "recon-"):
		return "Confirm whether schema, console, stack-trace, or implementation details are intentionally exposed to this caller."
	case strings.HasPrefix(category, "bypassauthz-"):
		return "Verify resolver-level authorization and whether aliases, operation names, client-controlled cookies, or token arguments alter access decisions."
	case strings.HasPrefix(category, "inj-"):
		return "Trace the named field or argument into backend query, render, or log sinks before attempting active payload validation."
	case strings.HasPrefix(category, "exec-") || strings.HasPrefix(category, "misc-filewrite"):
		return "Trace the named field or argument to subprocess, file-system, or server-side fetch behavior before attempting active validation."
	default:
		return "Use the operation, field, arguments, and proof excerpt as review context; LLM or human notes should not override deterministic scanner evidence."
	}
}

func limitString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "\n...[truncated]"
}

const graphqlReviewIntrospectionQuery = `query NyxSchemaReview {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind
      name
      fields {
        name
        args { name }
        type { kind name ofType { kind name ofType { kind name } } }
      }
    }
  }
}`
