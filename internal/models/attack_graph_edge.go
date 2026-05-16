package models

import "time"

type EdgeRelation string

const (
	RelationEnables   EdgeRelation = "enables"
	RelationAmplifies EdgeRelation = "amplifies"
	RelationRequires  EdgeRelation = "requires"
	RelationConfirms  EdgeRelation = "confirms"
)

type AttackGraphEdge struct {
	ID         string       `json:"id"`
	SessionID  string       `json:"session_id"`
	FromID     string       `json:"from_id"`
	ToID       string       `json:"to_id"`
	Relation   EdgeRelation `json:"relation"`
	Confidence float64      `json:"confidence"`
	CreatedAt  time.Time    `json:"created_at"`
}
