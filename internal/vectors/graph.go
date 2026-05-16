package vectors

import (
	"strings"
	"time"

	"github.com/pridhvi/nox/internal/models"
)

type FindingNode struct {
	ID            string
	Finding       *models.Finding
	SourceFinding *models.SourceFinding
	Weight        float64
}

type AttackGraph struct {
	Nodes []FindingNode
	Edges []models.AttackGraphEdge
}

func BuildAttackGraph(sessionID string, findings []models.Finding, sourceFindings []models.SourceFinding) AttackGraph {
	var graph AttackGraph
	for _, finding := range findings {
		f := finding
		graph.Nodes = append(graph.Nodes, FindingNode{ID: "finding:" + finding.ID, Finding: &f, Weight: weightFinding(finding)})
	}
	for _, sourceFinding := range sourceFindings {
		if sourceFinding.Kind != models.SourceKindSQLSink && sourceFinding.Kind != models.SourceKindSSRFSink && sourceFinding.Kind != models.SourceKindUnprotectedRoute {
			continue
		}
		sf := sourceFinding
		graph.Nodes = append(graph.Nodes, FindingNode{ID: "source:" + sourceFinding.ID, SourceFinding: &sf, Weight: 0.35})
	}
	for _, sourceFinding := range sourceFindings {
		for _, finding := range findings {
			if confirms(sourceFinding, finding) {
				graph.Edges = append(graph.Edges, edge(sessionID, "source:"+sourceFinding.ID, "finding:"+finding.ID, models.RelationConfirms, 0.85))
			}
		}
	}
	for _, from := range findings {
		for _, to := range findings {
			if from.ID == to.ID {
				continue
			}
			if relation, ok := findingRelation(from, to); ok {
				graph.Edges = append(graph.Edges, edge(sessionID, "finding:"+from.ID, "finding:"+to.ID, relation, 0.65))
			}
		}
	}
	return graph
}

func VectorsFromGraph(sessionID string, graph AttackGraph) []models.AttackVector {
	var vectors []models.AttackVector
	for _, edge := range graph.Edges {
		if edge.Relation != models.RelationConfirms && edge.Relation != models.RelationEnables && edge.Relation != models.RelationAmplifies {
			continue
		}
		to := strings.TrimPrefix(edge.ToID, "finding:")
		if to == edge.ToID {
			continue
		}
		vectors = append(vectors, models.AttackVector{
			ID:               models.NewID(),
			SessionID:        sessionID,
			Title:            "Graph-derived attack path",
			Description:      "A weighted relationship graph linked source, audit, and dynamic evidence.",
			Narrative:        "Nox correlated static or dynamic evidence into a higher-confidence attack path.",
			OWASPCategory:    "Composite Risk",
			Severity:         models.SeverityHigh,
			Confidence:       clamp(edge.Confidence + 0.1),
			PrereqFindingIDs: []string{to},
			Steps: []models.AttackStep{
				{Order: 1, Description: "Review the correlated graph edge: " + string(edge.Relation), FindingID: to},
				{Order: 2, Description: "Manually verify the end-to-end exploitability of this path."},
			},
			CreatedAt: time.Now().UTC(),
		})
	}
	if len(vectors) > 10 {
		return vectors[:10]
	}
	return vectors
}

func edge(sessionID, from, to string, relation models.EdgeRelation, confidence float64) models.AttackGraphEdge {
	return models.AttackGraphEdge{ID: models.NewID(), SessionID: sessionID, FromID: from, ToID: to, Relation: relation, Confidence: confidence, CreatedAt: time.Now().UTC()}
}

func confirms(sourceFinding models.SourceFinding, finding models.Finding) bool {
	if !strings.HasPrefix(finding.ToolID, "audit/") && sourceFinding.Value != "" && strings.Contains(strings.ToLower(finding.URL+" "+finding.Parameter+" "+finding.Title), strings.ToLower(sourceFinding.Value)) {
		return true
	}
	path := strings.TrimPrefix(finding.URL, "file://")
	if idx := strings.Index(path, "#"); idx >= 0 {
		path = path[:idx]
	}
	return path != "" && strings.HasSuffix(path, sourceFinding.FilePath)
}

func findingRelation(from, to models.Finding) (models.EdgeRelation, bool) {
	text := strings.ToLower(from.Title + " " + strings.Join(from.Tags, " "))
	target := strings.ToLower(to.Title + " " + strings.Join(to.Tags, " "))
	switch {
	case strings.Contains(text, "xss") && strings.Contains(target, "csp"):
		return models.RelationAmplifies, true
	case strings.Contains(text, "sql"):
		return models.RelationAmplifies, true
	case strings.Contains(text, "ssrf") && strings.Contains(target, "metadata"):
		return models.RelationEnables, true
	case strings.HasPrefix(from.ToolID, "audit/") && !strings.HasPrefix(to.ToolID, "audit/") && (from.Parameter == to.Parameter || from.URL == to.URL):
		return models.RelationConfirms, true
	default:
		return "", false
	}
}

func weightFinding(finding models.Finding) float64 {
	score := finding.CVSSScore
	if score == 0 {
		score = float64(severityRank(finding.Severity)) * 2
	}
	return score * finding.Confidence
}
