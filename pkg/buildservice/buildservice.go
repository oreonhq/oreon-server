package buildservice

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type BuildServiceClient struct {
	BaseURL  string
	Token    string
	Username string
	Password string
	mu       sync.Mutex
}

func NewBuildServiceClient() *BuildServiceClient {
	return &BuildServiceClient{
		BaseURL:  strings.TrimRight(os.Getenv("BUILD_SERVICE_URL"), "/"),
		Username: os.Getenv("BUILD_SERVICE_USERNAME"),
		Password: os.Getenv("BUILD_SERVICE_PASSWORD"),
	}
}

func (bsc *BuildServiceClient) ensureToken() error {
	bsc.mu.Lock()
	defer bsc.mu.Unlock()

	if bsc.Token != "" {
		return nil
	}

	body := map[string]string{
		"username": bsc.Username,
		"password": bsc.Password,
	}
	payload, _ := json.Marshal(body)

	resp, err := http.Post(bsc.BaseURL+"/api/auth/login", "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("login decode failed: %w", err)
	}

	bsc.Token = result.AccessToken
	return nil
}

func (bsc *BuildServiceClient) do(method, path string, body any) (*http.Response, error) {
	if err := bsc.ensureToken(); err != nil {
		return nil, err
	}

	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal failed: %w", err)
		}
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequest(method, bsc.BaseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bsc.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 300 * time.Second}
	return client.Do(req)
}

func (bsc *BuildServiceClient) get(path string) (*http.Response, error) {
	return bsc.do("GET", path, nil)
}

type ReleaseResponse struct {
	ID          int    `json:"id"`
	Releasename string `json:"releasename"`
}

type PaginatedReleases struct {
	Items []ReleaseResponse `json:"items"`
	Total int               `json:"total"`
}

func (bsc *BuildServiceClient) GetReleaseByName(name string) (*ReleaseResponse, error) {
	resp, err := bsc.get("/api/releases?limit=1000")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list releases HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var page PaginatedReleases
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, err
	}

	for _, r := range page.Items {
		if r.Releasename == name {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("release %q not found", name)
}

type CIChainTriggerRequest struct {
	Packages      []string `json:"packages"`
	DistgitBranch string   `json:"distgit_branch"`
	ReleaseID     int      `json:"release_id"`
	Architectures []string `json:"architectures"`
	DistgitURL    string   `json:"distgit_url,omitempty"`
	Priority      int      `json:"priority"`
}

type CIChainTriggerResponse struct {
	ChainID     int        `json:"chain_id"`
	ChainStatus string     `json:"chain_status"`
	Stages      [][]string `json:"stages"`
	ChainSpec   string     `json:"chain_spec"`
	Accepted    bool       `json:"accepted"`
	Message     string     `json:"message"`
}

func (bsc *BuildServiceClient) TriggerCIChainBuild(req CIChainTriggerRequest) (*CIChainTriggerResponse, error) {
	resp, err := bsc.do("POST", "/api/builds/ci-chain-trigger", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 201 {
		return nil, fmt.Errorf("ci-chain-trigger HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var result CIChainTriggerResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("ci-chain-trigger decode: %w", err)
	}
	return &result, nil
}

type ChainStatusResponse struct {
	ChainID          int        `json:"chain_id"`
	Status           string     `json:"status"`
	ActiveStageIndex int        `json:"active_stage_index"`
	Stages           [][]string `json:"stages"`
	ChainSpec        string     `json:"chain_spec"`
	ErrorMessage     *string    `json:"error_message"`
	JobCount         int        `json:"job_count"`
	Releasename      *string    `json:"releasename"`
}

func (bsc *BuildServiceClient) GetChainStatus(chainID int) (*ChainStatusResponse, error) {
	resp, err := bsc.get(fmt.Sprintf("/api/builds/chain/%d/status", chainID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("chain status HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var result ChainStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

type BuildJobResponse struct {
	ID              int     `json:"id"`
	PackageID       int     `json:"package_id"`
	PackageName     *string `json:"package_name"`
	ReleaseID       int     `json:"release_id"`
	ReleaseName     *string `json:"release_name"`
	Architecture    *string `json:"architecture"`
	Status          string  `json:"status"`
	DisplayStatus   string  `json:"display_status"`
	SigningStatus   *string `json:"signing_status"`
	Priority        int     `json:"priority"`
	ChainID         *int    `json:"chain_id"`
	ChainStageIndex *int    `json:"chain_stage_index"`
}

type PaginatedJobs struct {
	Items []BuildJobResponse `json:"items"`
	Total int                `json:"total"`
}

func (bsc *BuildServiceClient) GetChainJobs(chainID int) ([]BuildJobResponse, error) {
	resp, err := bsc.get(fmt.Sprintf("/api/builds?chain_id=%d&limit=1000", chainID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list chain jobs HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var page PaginatedJobs
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, err
	}
	return page.Items, nil
}

type BuildAttemptResponse struct {
	ID            int     `json:"id"`
	BuildJobID    int     `json:"build_job_id"`
	AttemptNumber int     `json:"attempt_number"`
	Status        string  `json:"status"`
	DisplayStatus string  `json:"display_status"`
	ErrorMessage  *string `json:"error_message"`
	LogR2Key      *string `json:"log_r2_key"`
}

func (bsc *BuildServiceClient) GetJobAttempts(jobID int) ([]BuildAttemptResponse, error) {
	resp, err := bsc.get(fmt.Sprintf("/api/builds/jobs/%d/attempts", jobID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list attempts HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var attempts []BuildAttemptResponse
	if err := json.NewDecoder(resp.Body).Decode(&attempts); err != nil {
		return nil, err
	}
	return attempts, nil
}

func (bsc *BuildServiceClient) GetLogTail(attemptID int, lines int) (string, error) {
	resp, err := bsc.get(fmt.Sprintf("/api/logs/attempts/%d/tail?lines=%d", attemptID, lines))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("log tail HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var result struct {
		Lines []string `json:"lines"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return strings.Join(result.Lines, "\n"), nil
}
