package cve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

type HTTPClient struct {
	name    string
	baseURL string
	client  *http.Client
}

func NewNVDClient(client *http.Client, baseURL string) HTTPClient {
	return newHTTPClient("nvd", client, firstNonEmpty(baseURL, "https://services.nvd.nist.gov/rest/json/cves/2.0"))
}

func NewOSVClient(client *http.Client, baseURL string) HTTPClient {
	return newHTTPClient("osv", client, firstNonEmpty(baseURL, "https://api.osv.dev/v1/query"))
}

func NewCIRCLClient(client *http.Client, baseURL string) HTTPClient {
	return newHTTPClient("circl", client, firstNonEmpty(baseURL, "https://cve.circl.lu/api/search"))
}

func NewVulnersClient(client *http.Client, baseURL string) HTTPClient {
	return newHTTPClient("vulners", client, firstNonEmpty(baseURL, "https://vulners.com/api/v3/search/lucene/"))
}

func NewGitHubAdvisoryClient(client *http.Client, baseURL string) HTTPClient {
	return newHTTPClient("github-advisories", client, firstNonEmpty(baseURL, "https://api.github.com/advisories"))
}

func newHTTPClient(name string, client *http.Client, baseURL string) HTTPClient {
	if client == nil {
		client = http.DefaultClient
	}
	return HTTPClient{name: name, baseURL: baseURL, client: client}
}

func (c HTTPClient) Name() string { return c.name }

func (c HTTPClient) Search(ctx context.Context, product, version string) ([]Advisory, error) {
	switch c.name {
	case "nvd":
		return c.searchNVD(ctx, product, version)
	default:
		return nil, nil
	}
}

func (c HTTPClient) searchNVD(ctx context.Context, product, version string) ([]Advisory, error) {
	endpoint, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, err
	}
	query := endpoint.Query()
	query.Set("keywordSearch", product+" "+version)
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CVSSMetricV31 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							VectorString string  `json:"vectorString"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
				References struct {
					ReferenceData []struct {
						URL string `json:"url"`
					} `json:"referenceData"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	var advisories []Advisory
	for _, item := range body.Vulnerabilities {
		advisory := Advisory{
			CVEID:           item.CVE.ID,
			Product:         product,
			AffectedVersion: version,
			Source:          c.name,
		}
		for _, description := range item.CVE.Descriptions {
			if description.Lang == "en" {
				advisory.Description = description.Value
				break
			}
		}
		if len(item.CVE.Metrics.CVSSMetricV31) > 0 {
			advisory.CVSSv3Score = item.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
			advisory.CVSSv3Vector = item.CVE.Metrics.CVSSMetricV31[0].CVSSData.VectorString
		}
		for _, ref := range item.CVE.References.ReferenceData {
			advisory.References = append(advisory.References, ref.URL)
		}
		advisories = append(advisories, advisory)
	}
	return advisories, nil
}
