package activedirectory

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
)

func InternalSession(session models.Session, targets []models.Target) bool {
	for _, scope := range session.InScope {
		if internalHost(scope) {
			return true
		}
	}
	for _, target := range targets {
		if internalHost(target.Host) || internalHost(target.IP) {
			return true
		}
	}
	return false
}

func internalHost(value string) bool {
	value = strings.TrimSpace(strings.TrimPrefix(value, "http://"))
	value = strings.TrimPrefix(value, "https://")
	host, _, _ := strings.Cut(value, "/")
	host, _, _ = strings.Cut(host, ":")
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

func RecordEnumRequest(ctx context.Context, store *db.Store, session models.Session, domain string, allowPublic bool) ([]models.ADEntity, error) {
	targets, err := store.ListTargets(ctx, session.ID)
	if err != nil {
		return nil, err
	}
	if !allowPublic && !InternalSession(session, targets) {
		return nil, fmt.Errorf("AD enumeration requires private/link-local/loopback scope or explicit override")
	}
	entity := models.ADEntity{
		ID:         models.NewID(),
		SessionID:  session.ID,
		EntityType: "domain",
		Name:       strings.TrimSpace(domain),
		Domain:     strings.TrimSpace(domain),
		Metadata:   map[string]any{"status": "enumeration_request_recorded", "external_tools": "optional"},
		CreatedAt:  time.Now().UTC(),
	}
	if entity.Name == "" {
		entity.Name = "unknown-domain"
	}
	if err := store.InsertADEntity(ctx, entity); err != nil {
		return nil, err
	}
	for _, target := range targets {
		if strings.EqualFold(target.Protocol, "smb") || target.Port == 445 {
			_ = store.InsertADEntity(ctx, models.ADEntity{
				ID:         models.NewID(),
				SessionID:  session.ID,
				EntityType: "smb_service",
				Name:       firstNonEmpty(target.Host, target.IP),
				Domain:     entity.Domain,
				Metadata:   map[string]any{"relay_risk": "unknown", "safe_enum": true},
				CreatedAt:  time.Now().UTC(),
			})
		}
	}
	return store.ListADEntities(ctx, session.ID, "")
}

type KerberoastRequest struct {
	Domain      string `json:"domain"`
	Username    string `json:"username"`
	Confirm     bool   `json:"confirm"`
	AllowPublic bool   `json:"allow_public"`
}

func RecordKerberoastRequest(ctx context.Context, store *db.Store, session models.Session, req KerberoastRequest) (models.ADArtifact, error) {
	if !req.Confirm {
		return models.ADArtifact{}, fmt.Errorf("kerberoast requires confirm=true")
	}
	targets, err := store.ListTargets(ctx, session.ID)
	if err != nil {
		return models.ADArtifact{}, err
	}
	if !req.AllowPublic && !InternalSession(session, targets) {
		return models.ADArtifact{}, fmt.Errorf("kerberoast requires private/link-local/loopback scope or explicit override")
	}
	now := time.Now().UTC()
	artifact := models.ADArtifact{
		ID:           models.NewID(),
		SessionID:    session.ID,
		ArtifactType: "kerberoast_request",
		Summary:      "Kerberoast request recorded. Hash extraction and cracking are not performed automatically by Nyx.",
		CreatedAt:    now,
	}
	if req.Domain != "" || req.Username != "" {
		artifact.Summary += fmt.Sprintf(" domain=%s username=%s", strings.TrimSpace(req.Domain), strings.TrimSpace(req.Username))
	}
	if err := store.InsertADArtifact(ctx, artifact); err != nil {
		return models.ADArtifact{}, err
	}
	return artifact, nil
}

func RecordRelayRisks(ctx context.Context, store *db.Store, session models.Session) ([]models.ADEntity, error) {
	targets, err := store.ListTargets(ctx, session.ID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	for _, target := range targets {
		if target.Port != 445 && target.Port != 389 && !strings.EqualFold(target.Protocol, "smb") && !strings.EqualFold(target.Protocol, "ldap") {
			continue
		}
		_ = store.InsertADEntity(ctx, models.ADEntity{
			ID:         models.NewID(),
			SessionID:  session.ID,
			EntityType: "relay_opportunity",
			Name:       firstNonEmpty(target.Host, target.IP),
			Domain:     "",
			Metadata: map[string]any{
				"port":       target.Port,
				"protocol":   target.Protocol,
				"risk":       "requires manual validation of signing/channel-binding settings",
				"non_active": true,
			},
			CreatedAt: now,
		})
	}
	return store.ListADEntities(ctx, session.ID, "relay_opportunity")
}

type BloodHoundData struct {
	Nodes []struct {
		ID     string         `json:"id"`
		Name   string         `json:"name"`
		Type   string         `json:"type"`
		Domain string         `json:"domain"`
		SID    string         `json:"sid"`
		Props  map[string]any `json:"props"`
	} `json:"nodes"`
	Edges []struct {
		From     string         `json:"from"`
		To       string         `json:"to"`
		Relation string         `json:"relation"`
		Props    map[string]any `json:"props"`
	} `json:"edges"`
}

func ImportBloodHound(ctx context.Context, store *db.Store, sessionID string, raw []byte) error {
	var data BloodHoundData
	if err := json.Unmarshal(raw, &data); err != nil {
		return err
	}
	idMap := map[string]string{}
	now := time.Now().UTC()
	for _, node := range data.Nodes {
		id := models.NewID()
		sourceID := node.ID
		if sourceID == "" {
			sourceID = node.Name
		}
		idMap[sourceID] = id
		entityType := strings.ToLower(strings.TrimSpace(node.Type))
		if entityType == "" {
			entityType = "unknown"
		}
		if err := store.InsertADEntity(ctx, models.ADEntity{
			ID:         id,
			SessionID:  sessionID,
			EntityType: entityType,
			Name:       node.Name,
			Domain:     node.Domain,
			SID:        node.SID,
			Metadata:   node.Props,
			CreatedAt:  now,
		}); err != nil {
			return err
		}
	}
	for _, edge := range data.Edges {
		fromID := idMap[edge.From]
		toID := idMap[edge.To]
		if fromID == "" || toID == "" {
			continue
		}
		relation := strings.TrimSpace(edge.Relation)
		if relation == "" {
			relation = "related"
		}
		if err := store.InsertADRelationship(ctx, models.ADRelationship{
			ID:           models.NewID(),
			SessionID:    sessionID,
			FromEntityID: fromID,
			ToEntityID:   toID,
			Relation:     relation,
			Metadata:     edge.Props,
			CreatedAt:    now,
		}); err != nil {
			return err
		}
	}
	return store.InsertADArtifact(ctx, models.ADArtifact{ID: models.NewID(), SessionID: sessionID, ArtifactType: "bloodhound_import", Summary: fmt.Sprintf("Imported %d nodes and %d edges", len(data.Nodes), len(data.Edges)), CreatedAt: now})
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
