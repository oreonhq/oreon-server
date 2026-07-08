package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v53/github"

	"github.com/oreonhq/bot/pkg/buildservice"
)

type ciCallbackPayload struct {
	ChainID      int    `json:"chain_id"`
	Status       string `json:"status"`
	ErrorMessage string `json:"error_message"`
}

type ciCheckExternalID struct {
	ChainID    int    `json:"chain_id"`
	PRNumber   int    `json:"pr_number"`
	HeadSHA    string `json:"head_sha"`
	HeadBranch string `json:"head_branch"`
	BaseBranch string `json:"base_branch"`
}

func BuildCallbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	cbSecret := os.Getenv("CI_CALLBACK_SECRET")
	if cbSecret != "" {
		provided := r.Header.Get("X-CI-Callback-Secret")
		if provided != cbSecret {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	var payload ciCallbackPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if payload.ChainID == 0 {
		http.Error(w, "Missing chain_id", http.StatusBadRequest)
		return
	}

	log.Printf("BuildCallback: chain_id=%d status=%s", payload.ChainID, payload.Status)

	go processChainCallback(payload)

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "accepted")
}

func processChainCallback(payload ciCallbackPayload) {
	ctx := context.Background()

	rawAppID := strings.TrimSpace(os.Getenv("GITHUB_APP_ID"))
	appID, err := strconv.ParseInt(rawAppID, 10, 64)
	if err != nil {
		log.Printf("BuildCallback: parse GITHUB_APP_ID: %v", err)
		return
	}

	rawKey := strings.TrimSpace(os.Getenv("GITHUB_PRIVATE_KEY"))
	rawKey = strings.Trim(rawKey, `"'`)
	rawKey = strings.ReplaceAll(rawKey, "\\n", "\n")

	instID, err := findInstallationID(ctx, appID, rawKey)
	if err != nil {
		log.Printf("BuildCallback: find installation: %v", err)
		return
	}

	itr, err := ghinstallation.New(http.DefaultTransport, appID, instID, []byte(rawKey))
	if err != nil {
		log.Printf("BuildCallback: auth: %v", err)
		return
	}
	client := github.NewClient(&http.Client{Transport: itr})

	org := "oreonhq"
	repo := "rpm-specfiles"

	prNum, headSHA, checkRunID, err := findCheckRunForChain(ctx, client, org, repo, payload.ChainID)
	if err != nil {
		log.Printf("BuildCallback: find check run for chain %d: %v", payload.ChainID, err)
		return
	}
	if checkRunID == 0 {
		log.Printf("BuildCallback: no in-progress RPM Build check run found for chain %d", payload.ChainID)
		return
	}

	buildClient := buildservice.NewBuildServiceClient()

	switch payload.Status {
	case "success":
		err = finalizeChainSuccess(ctx, client, buildClient, org, repo, prNum, headSHA, checkRunID, payload.ChainID)
	case "failed", "cancelled":
		err = finalizeChainFailure(ctx, client, buildClient, org, repo, prNum, headSHA, checkRunID, payload.ChainID, payload.Status, payload.ErrorMessage)
	default:
		log.Printf("BuildCallback: ignoring chain %d status %s", payload.ChainID, payload.Status)
		return
	}

	if err != nil {
		log.Printf("BuildCallback: chain %d finalize: %v", payload.ChainID, err)
	}
}

func findInstallationID(ctx context.Context, appID int64, rawKey string) (int64, error) {
 itr, err := ghinstallation.New(http.DefaultTransport, appID, 0, []byte(rawKey))
	if err != nil {
		return 0, err
	}
	appClient := github.NewClient(&http.Client{Transport: itr})
	installs, _, err := appClient.Apps.ListInstallations(ctx, nil)
	if err != nil {
		return 0, err
	}
	for _, inst := range installs {
		if inst.Account != nil && inst.Account.GetLogin() == "oreonhq" {
			return inst.GetID(), nil
		}
	}
	if len(installs) > 0 {
		return installs[0].GetID(), nil
	}
	return 0, fmt.Errorf("no installations found")
}

func findCheckRunForChain(ctx context.Context, client *github.Client, org, repo string, chainID int) (prNum int, headSHA string, checkRunID int64, err error) {
	prs, _, lerr := client.PullRequests.List(ctx, org, repo, &github.PullRequestListOptions{
		State:       "open",
		ListOptions: github.ListOptions{PerPage: 100},
	})
	if lerr != nil {
		return 0, "", 0, fmt.Errorf("list PRs: %w", lerr)
	}

	target := fmt.Sprintf(`"chain_id":%d`, chainID)

	for _, pr := range prs {
		sha := pr.GetHead().GetSHA()
		if sha == "" {
			continue
		}

		runs, _, rerr := client.Checks.ListCheckRunsForRef(ctx, org, repo, sha, &github.ListCheckRunsOptions{
			CheckName: github.String("RPM Build"),
			Filter:    github.String("latest"),
		})
		if rerr != nil {
			continue
		}

		for _, cr := range runs.CheckRuns {
			if cr.GetStatus() != "in_progress" {
				continue
			}
			ext := cr.GetExternalID()
			if ext == "" || !strings.Contains(ext, target) {
				continue
			}
			return pr.GetNumber(), sha, cr.GetID(), nil
		}
	}
	return 0, "", 0, nil
}

func finalizeChainSuccess(
	ctx context.Context,
	client *github.Client,
	buildClient *buildservice.BuildServiceClient,
	org, repo string,
	prNum int,
	headSHA string,
	checkRunID int64,
	chainID int,
) error {
	status, err := buildClient.GetChainStatus(chainID)
	if err != nil {
		return fmt.Errorf("get chain status: %w", err)
	}

	jobs, err := buildClient.GetChainJobs(chainID)
	if err != nil {
		return fmt.Errorf("get chain jobs: %w", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("✅ **RPM Build Succeeded** — all %d job(s) completed.\n\n", len(jobs)))
	sb.WriteString(fmt.Sprintf("**Chain spec:** `%s`\n", status.ChainSpec))
	if len(status.Stages) > 0 {
		sb.WriteString("\n**Build stages:**\n")
		for i, stage := range status.Stages {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, strings.Join(stage, ", ")))
		}
	}
	sb.WriteString("\n**Jobs:**\n")
	for _, job := range jobs {
		arch := ""
		if job.Architecture != nil {
			arch = *job.Architecture
		}
		pkg := ""
		if job.PackageName != nil {
			pkg = *job.PackageName
		}
		sb.WriteString(fmt.Sprintf("- `%s` (%s) — %s\n", pkg, arch, job.DisplayStatus))
	}

	_, _, err = client.Checks.UpdateCheckRun(ctx, org, repo, checkRunID, github.UpdateCheckRunOptions{
		Name:       "RPM Build",
		Status:     github.String("completed"),
		Conclusion: github.String("success"),
		Output: &github.CheckRunOutput{
			Title:   github.String("RPM Build Passed"),
			Summary: github.String(sb.String()),
		},
	})
	if err != nil {
		return fmt.Errorf("update check run: %w", err)
	}
	return nil
}

func finalizeChainFailure(
	ctx context.Context,
	client *github.Client,
	buildClient *buildservice.BuildServiceClient,
	org, repo string,
	prNum int,
	headSHA string,
	checkRunID int64,
	chainID int,
	chainStatus string,
	errorMessage string,
) error {
	jobs, err := buildClient.GetChainJobs(chainID)
	if err != nil {
		return fmt.Errorf("get chain jobs: %w", err)
	}

	var failedJobs []buildservice.BuildJobResponse
	for _, job := range jobs {
		if job.Status == "failed" || job.DisplayStatus == "failed" {
			failedJobs = append(failedJobs, job)
		}
	}

	var sb strings.Builder
	if errorMessage != "" {
		sb.WriteString(fmt.Sprintf("❌ **RPM Build Failed** — %s\n\n", errorMessage))
	} else {
		sb.WriteString("❌ **RPM Build Failed**\n\n")
	}

	if len(failedJobs) == 0 {
		sb.WriteString("No failed jobs identified. The chain may have been cancelled.\n")
	} else {
		sb.WriteString(fmt.Sprintf("**Failed job(s):** %d\n\n", len(failedJobs)))
	}

	for _, job := range failedJobs {
		pkg := ""
		if job.PackageName != nil {
			pkg = *job.PackageName
		}
		arch := ""
		if job.Architecture != nil {
			arch = *job.Architecture
		}

		attempts, aErr := buildClient.GetJobAttempts(job.ID)
		if aErr != nil {
			sb.WriteString(fmt.Sprintf("### `%s` (%s)\n\n_build log unavailable: %v_\n\n", pkg, arch, aErr))
			continue
		}

		var latestFailed *buildservice.BuildAttemptResponse
		for i := range attempts {
			if attempts[i].Status == "failed" {
				latestFailed = &attempts[i]
				break
			}
		}

		sb.WriteString(fmt.Sprintf("### `%s` (%s)\n\n", pkg, arch))

		if latestFailed != nil {
			errMsg := "no error message"
			if latestFailed.ErrorMessage != nil && *latestFailed.ErrorMessage != "" {
				errMsg = *latestFailed.ErrorMessage
			}
			sb.WriteString(fmt.Sprintf("**Error:** `%s`\n\n", truncateForLog(errMsg, 500)))

			logTail, lErr := buildClient.GetLogTail(latestFailed.ID, 200)
			if lErr != nil {
				sb.WriteString(fmt.Sprintf("_Build log unavailable: %v_\n\n", lErr))
			} else if logTail != "" {
				logContent := logTail
				if len(logContent) > 60000 {
					logContent = logContent[:60000] + "\n... (truncated)"
				}
				sb.WriteString("<details>\n<summary>Build log (last 200 lines)</summary>\n\n")
				sb.WriteString("```\n")
				sb.WriteString(logContent)
				sb.WriteString("\n```\n\n</details>\n\n")
			} else {
				sb.WriteString("_Build log is empty._\n\n")
			}
		} else {
			sb.WriteString("_No failed attempt found._\n\n")
		}
	}

	conclusion := "failure"
	if chainStatus == "cancelled" {
		conclusion = "cancelled"
	}

	_, _, err = client.Checks.UpdateCheckRun(ctx, org, repo, checkRunID, github.UpdateCheckRunOptions{
		Name:       "RPM Build",
		Status:     github.String("completed"),
		Conclusion: github.String(conclusion),
		Output: &github.CheckRunOutput{
			Title:   github.String("RPM Build Failed"),
			Summary: github.String(truncateForLog(sb.String(), 65000)),
		},
	})
	if err != nil {
		return fmt.Errorf("update check run: %w", err)
	}

	commentBody := truncateForLog(sb.String(), 65000)
	_, _, err = client.Issues.CreateComment(ctx, org, repo, prNum, &github.IssueComment{
		Body: &commentBody,
	})
	if err != nil {
		log.Printf("BuildCallback: post PR comment failed for PR %d: %v", prNum, err)
	}

	return nil
}

func truncateForLog(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n... (truncated)"
}
