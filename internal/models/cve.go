package models

type CVEMatch struct {
	ID               string   `json:"id"`
	SessionID        string   `json:"session_id,omitempty"`
	FindingID        string   `json:"finding_id"`
	TechnologyID     string   `json:"technology_id,omitempty"`
	CVEID            string   `json:"cve_id"`
	CVSSv3Score      float64  `json:"cvss_v3_score"`
	CVSSv3Vector     string   `json:"cvss_v3_vector"`
	Description      string   `json:"description"`
	PackageName      string   `json:"package_name,omitempty"`
	PackageVersion   string   `json:"package_version,omitempty"`
	AffectedVersion  string   `json:"affected_version,omitempty"`
	FixedVersion     string   `json:"fixed_version,omitempty"`
	PatchAvailable   bool     `json:"patch_available"`
	ExploitAvailable bool     `json:"exploit_available"`
	References       []string `json:"references"`
	Source           string   `json:"source"`
	ConfidenceScore  float64  `json:"confidence_score"`
}
