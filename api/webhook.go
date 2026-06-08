package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/go-github/v53/github"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	webhookSecret := []byte(os.Getenv("GITHUB_WEBHOOK_SECRET"))

	payload, err := github.ValidatePayload(r, webhookSecret)
	if err != nil {
		log.Printf("Security Error: Invalid webhook signature: %v", err)
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	event, err := github.ParseWebHook(github.WebHookType(r), payload)
	if err != nil {
		log.Printf("Parse Error: Failed to decode webhook payload: %v", err)
		http.Error(w, "Failed to parse webhook", http.StatusBadRequest)
		return
	}

	rawAppID := strings.TrimSpace(os.Getenv("GITHUB_APP_ID"))
	appID, err := strconv.ParseInt(rawAppID, 10, 64)
	if err != nil {
		log.Printf("CRITICAL: Failed to parse GITHUB_APP_ID '%s': %v", rawAppID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	rawKey := strings.TrimSpace(os.Getenv("GITHUB_PRIVATE_KEY"))
	rawKey = strings.Trim(rawKey, `"'`)
	rawKey = strings.ReplaceAll(rawKey, "\\n", "\n")
	privateKey := []byte(rawKey)

	var instID int64
	switch e := event.(type) {
	case *github.IssueCommentEvent:
		if e.Installation != nil {
			instID = e.Installation.GetID()
		}
	case *github.PullRequestEvent:
		if e.Installation != nil {
			instID = e.Installation.GetID()
		}
	case *github.PullRequestReviewEvent:
		if e.Installation != nil {
			instID = e.Installation.GetID()
		}
	default:
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}

	if instID == 0 {
		log.Printf("Logic Error: No installation ID found in the webhook payload.")
		http.Error(w, "No installation ID found", http.StatusBadRequest)
		return
	}

	itr, err := ghinstallation.New(http.DefaultTransport, appID, instID, privateKey)
	if err != nil {
		log.Printf("CRITICAL: GitHub App authentication failed. Check private key formatting. Error: %v", err)
		http.Error(w, "Failed to authenticate", http.StatusInternalServerError)
		return
	}

	client := github.NewClient(&http.Client{Transport: itr})
	ctx := context.Background()

	switch e := event.(type) {
	case *github.IssueCommentEvent:
		handleIssueComment(ctx, client, e)
	case *github.PullRequestEvent:
		handlePullRequest(ctx, client, e)
	case *github.PullRequestReviewEvent:
		handlePullRequestReview(ctx, client, e)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func handleIssueComment(ctx context.Context, client *github.Client, e *github.IssueCommentEvent) {
	comment := strings.TrimSpace(e.Comment.GetBody())
	if comment != "/m" && comment != "/merge-ff" {
		return
	}

	if !e.Issue.IsPullRequest() {
		return
	}

	org := e.Repo.Owner.GetLogin()
	repo := e.Repo.GetName()
	commenter := e.Sender.GetLogin()
	prNum := e.Issue.GetNumber()

	_, _, err := client.Teams.GetTeamMembershipBySlug(ctx, org, repo, commenter)
	if err != nil {
		msg := fmt.Sprintf("❌ **Access Denied:** @%s, you are not a member of the `%s` maintainers team.", commenter, repo)
		client.Issues.CreateComment(ctx, org, repo, prNum, &github.IssueComment{Body: &msg})
		return
	}

	pr, _, err := client.PullRequests.Get(ctx, org, repo, prNum)
	if err != nil {
		return
	}

	ref := fmt.Sprintf("heads/%s", pr.Base.GetRef())
	sha := pr.Head.GetSHA()
	force := false

	_, _, err = client.Git.UpdateRef(ctx, org, repo, &github.Reference{
		Ref:    &ref,
		Object: &github.GitObject{SHA: &sha},
	}, force)

	if err != nil {
		msg := fmt.Sprintf("❌ **Merge Failed:** GitHub rejected the fast-forward.\n\n`%v`", err)
		client.Issues.CreateComment(ctx, org, repo, prNum, &github.IssueComment{Body: &msg})
		return
	}

	msg := fmt.Sprintf("✅ **Fast-Forward Merge Complete:** Successfully advanced `%s` to `%s`.", pr.Base.GetRef(), sha)
	client.Issues.CreateComment(ctx, org, repo, prNum, &github.IssueComment{Body: &msg})
}

func handlePullRequest(ctx context.Context, client *github.Client, e *github.PullRequestEvent) {
	action := e.GetAction()
	if action != "opened" && action != "synchronize" {
		return
	}

	org := e.Repo.Owner.GetLogin()
	repo := e.Repo.GetName()
	author := e.PullRequest.User.GetLogin()
	prNum := e.PullRequest.GetNumber()
	headSHA := e.PullRequest.Head.GetSHA()

	// -----------------------------------------
	// FEATURE 1: TEAM APPROVAL VERIFICATION
	// -----------------------------------------
	_, _, err := client.Teams.GetTeamMembershipBySlug(ctx, org, repo, author)
	if err == nil {
		// Author is a maintainer: Submit the automated review
		body := fmt.Sprintf("🤖 **Auto-Approved:** PR authored by an authorized maintainer (@%s).", author)
		client.PullRequests.CreateReview(ctx, org, repo, prNum, &github.PullRequestReviewRequest{
			Event: github.String("APPROVE"),
			Body:  &body,
		})

		// Generate a Success Check Run
		client.Checks.CreateCheckRun(ctx, org, repo, github.CreateCheckRunOptions{
			Name:       "Team Approval Verification",
			HeadSHA:    headSHA,
			Status:     github.String("completed"),
			Conclusion: github.String("success"),
			Output: &github.CheckRunOutput{
				Title:   github.String("Maintainer Auto-Approved"),
				Summary: github.String(fmt.Sprintf("PR was auto-approved because the author (@%s) is an authorized maintainer.", author)),
			},
		})
	} else {
		// Author is a community member: Generate a Failure/Pending Check Run
		client.Checks.CreateCheckRun(ctx, org, repo, github.CreateCheckRunOptions{
			Name:       "Team Approval Verification",
			HeadSHA:    headSHA,
			Status:     github.String("completed"),
			Conclusion: github.String("failure"),
			Output: &github.CheckRunOutput{
				Title:   github.String("Awaiting Maintainer Review"),
				Summary: github.String("This PR was opened by a community contributor. An authorized maintainer must approve it before merging."),
			},
		})
	}

	// -----------------------------------------
	// FEATURE 2: TEAM SIGNATURE VERIFICATION
	// -----------------------------------------

	checkRun, _, err := client.Checks.CreateCheckRun(ctx, org, repo, github.CreateCheckRunOptions{
		Name:    "Team Signature Verification",
		HeadSHA: headSHA,
		Status:  github.String("in_progress"),
	})
	if err != nil {
		fmt.Printf("Failed to create initial check run: %v\n", err)
	}

	commits, _, err := client.PullRequests.ListCommits(ctx, org, repo, prNum, nil)
	if err != nil {
		return
	}

	allValid := true

	// FIX 1: Fetch from the Fork's repository (Head), not the Base repository!
	repoURL := e.PullRequest.Head.Repo.GetCloneURL()
	prBranchRef := e.PullRequest.Head.GetRef()

	for _, commit := range commits {
		sha := commit.GetSHA()

		// FIX 2: Identify the specific GitHub user who authored the commit
		var username string
		if commit.Author != nil && commit.Author.GetLogin() != "" {
			username = commit.Author.GetLogin()
		} else if commit.Committer != nil && commit.Committer.GetLogin() != "" {
			username = commit.Committer.GetLogin()
		}

		if username == "" {
			fmt.Printf("Commit %s has no linked GitHub user\n", sha)
			allValid = false
			break
		}

		// FIX 3: Fetch ONLY that specific user's public key (e.g., "andrinoff.txt")
		keyPath := fmt.Sprintf("%s.txt", username)
		fileContent, _, _, err := client.Repositories.GetContents(ctx, "oreonhq", "team-sigs", keyPath, nil)

		if err != nil || fileContent == nil {
			fmt.Printf("No public key found in oreonhq/team-sigs for user: %s\n", username)
			allValid = false
			break
		}

		asciiKey, _ := fileContent.GetContent()

		valid, err := verifyCommit(repoURL, prBranchRef, sha, asciiKey)
		if !valid {
			fmt.Printf("Verification failed for %s: %v\n", sha, err)
			allValid = false
			break
		}
	}

	conclusion := "success"
	title := "Verification Passed"
	summary := "All commits in this PR were successfully cryptographically verified against the team keyring."

	if !allValid {
		conclusion = "failure"
		title = "Verification Failed"
		summary = "Cryptographic verification failed for one or more commits. Ensure all commits are signed by an authorized team member."
	}

	if checkRun != nil {
		_, _, err = client.Checks.UpdateCheckRun(ctx, org, repo, checkRun.GetID(), github.UpdateCheckRunOptions{
			Status:     github.String("completed"),
			Conclusion: github.String(conclusion),
			Output: &github.CheckRunOutput{
				Title:   github.String(title),
				Summary: github.String(summary),
			},
		})
		if err != nil {
			fmt.Printf("Failed to update check run: %v\n", err)
		}
	}
}

func handlePullRequestReview(ctx context.Context, client *github.Client, e *github.PullRequestReviewEvent) {
	if e.GetAction() != "submitted" || e.Review.GetState() != "approved" {
		return
	}

	org := e.Repo.Owner.GetLogin()
	repo := e.Repo.GetName()
	reviewer := e.Review.User.GetLogin()
	headSHA := e.PullRequest.Head.GetSHA()

	_, _, err := client.Teams.GetTeamMembershipBySlug(ctx, org, repo, reviewer)
	if err != nil {
		return
	}

	// Update the community PR's approval check run to green
	_, _, err = client.Checks.CreateCheckRun(ctx, org, repo, github.CreateCheckRunOptions{
		Name:       "Team Approval Verification",
		HeadSHA:    headSHA,
		Status:     github.String("completed"),
		Conclusion: github.String("success"),
		Output: &github.CheckRunOutput{
			Title:   github.String("Manual Approval Verified"),
			Summary: github.String(fmt.Sprintf("Authorized maintainer @%s has officially approved this PR.", reviewer)),
		},
	})
	if err != nil {
		fmt.Printf("Failed to update check run for review: %v\n", err)
	}
}

func verifyCommit(repoURL, prBranchRef, commitSHA, asciiPublicKey string) (bool, error) {
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(asciiPublicKey))
	if err != nil {
		return false, fmt.Errorf("err: %v", err)
	}

	repo, err := git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
		URL: repoURL,
	})
	if err != nil {
		return false, fmt.Errorf("err: %v", err)
	}

	err = repo.Fetch(&git.FetchOptions{
		RefSpecs: []config.RefSpec{config.RefSpec(fmt.Sprintf("+%s:%s", prBranchRef, prBranchRef))},
	})
	if err != nil && err != git.NoErrAlreadyUpToDate {
		return false, fmt.Errorf("err: %v", err)
	}

	hash := plumbing.NewHash(commitSHA)
	commit, err := repo.CommitObject(hash)
	if err != nil {
		return false, fmt.Errorf("err: %v", err)
	}

	if commit.PGPSignature == "" {
		return false, fmt.Errorf("err: no sig")
	}

	obj := &plumbing.MemoryObject{}
	err = commit.EncodeWithoutSignature(obj)
	if err != nil {
		return false, fmt.Errorf("err: %v", err)
	}

	reader, err := obj.Reader()
	if err != nil {
		return false, fmt.Errorf("err: %v", err)
	}

	signature := strings.NewReader(commit.PGPSignature)

	_, err = openpgp.CheckArmoredDetachedSignature(keyring, reader, signature, nil)
	if err != nil {
		return false, fmt.Errorf("err: %v", err)
	}

	return true, nil
}
