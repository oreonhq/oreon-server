package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v53/github"
)

const gpl3License = `                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

                            Preamble

  The GNU General Public License is a free, copyleft license for
software and other kinds of works.

  For the precise terms and conditions for copying, distribution and
modification, follow the Terms and Conditions below.

                       TERMS AND CONDITIONS

  0. Definitions.

  "This License" refers to version 3 of the GNU General Public License.

  "The Program" refers to any copyrightable work licensed under this
License.  Each licensee is addressed as "you".  "Licensees" and
"recipients" may be individuals or organizations.

  To "modify" a work means to copy from or adapt all or part of the work
in a fashion requiring copyright permission, other than the making of an
exact copy.  The resulting work is called a "modified version" of the
earlier work or a work "based on" the earlier work.

  A "covered work" means either the unmodified Program or a work based
on the Program.

  To "propagate" a work means to do anything with it that, without
permission, would make you directly or secondarily liable for
infringement under applicable copyright law, except executing it on a
computer or transmitting it to third parties.

  To "convey" a work means any kind of propagation that enables other
parties to make or receive copies.  Mere interaction with a user through
a computer network, with no transfer of a copy, is not conveying.

  1. Source Code.

  The "source code" for a work means the preferred form of the work
for making modifications to it.  "Object code" means any non-source
form of a work.

  2. Basic Permissions.

  All rights granted under this License are granted for the term of
copyright on the Program, and are irrevocable provided the stated
conditions are met.  This License explicitly affirms your unlimited
permission to run the unmodified Program.

  3. Protecting Users' Legal Rights From Anti-Circumvention Law.

  No covered work shall be deemed part of an effective technological
measure under any applicable law fulfilling obligations under article
11 of the WIPO copyright treaty adopted on 20 December 1996.

  4. Conveying Verbatim Copies.

  You may convey verbatim copies of the Program's source code as you
receive it, in any medium, provided that you conspicuously and
appropriately publish on each copy an appropriate copyright notice.

  5. Conveying Modified Source Versions.

  You may convey a work based on the Program, or the modifications to
produce it from the Program, in the form of source code under the
terms of section 4, provided that you also meet all of these conditions:

    a) The work must carry prominent notices stating that you modified
    it, and giving a relevant date.

    b) The work must carry prominent notices stating that it is
    released under this License and any conditions added under section 7.

    c) You must license the entire work, as a whole, under this
    License to anyone who comes into possession of a copy.

  6. Conveying Non-Source Forms.

  You may convey a covered work in object code form under the terms
of sections 4 and 5, provided that you also convey the machine-readable
Corresponding Source under the terms of this License.

  7. Additional Terms.

  "Additional permissions" are terms that supplement the terms of this
License by making exceptions from one or more of its conditions.

  8. Termination.

  You may not propagate or modify a covered work except as expressly
provided under this License.

  9. Acceptance Not Required for Having Copies.

  You are not required to accept this License in order to receive or
run a copy of the Program.

  10. Automatic Licensing of Downstream Recipients.

  Each time you convey a covered work, the recipient automatically
receives a license from the original licensors, to run, modify and
propagate that work, subject to this License.

  11. Patents.

  Each contributor grants you a non-exclusive, worldwide, royalty-free
patent license under the contributor's essential patent claims, to
make, use, sell, offer for sale, import and otherwise run, modify and
propagate the contents of its contributor version.

  12. No Surrender of Others' Freedom.

  If conditions are imposed on you that contradict the conditions of
this License, they do not excuse you from the conditions of this License.

  13. Use with the GNU Affero General Public License.

  Notwithstanding any other provision of this License, you have
permission to link or combine any covered work with a work licensed
under version 3 of the GNU Affero General Public License into a single
combined work, and to convey the resulting work.

  14. Revised Versions of this License.

  The Free Software Foundation may publish revised and/or new versions of
the GNU General Public License from time to time.

  15. Disclaimer of Warranty.

  THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW.

  16. Limitation of Liability.

  IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER BE LIABLE TO YOU FOR DAMAGES.

  17. Interpretation of Sections 15 and 16.

  If the disclaimer of warranty and limitation of liability provided
above cannot be given local legal effect according to their terms,
reviewing courts shall apply local law that most closely approximates
an absolute waiver of all civil liability in connection with the Program.

                     END OF TERMS AND CONDITIONS
`

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
	case *github.RepositoryEvent:
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
	case *github.RepositoryEvent:
		handleRepositoryCreated(ctx, client, e)
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

	headSHA := pr.Head.GetSHA()

	conclusionFor := func(name string) string {
		result, _, e := client.Checks.ListCheckRunsForRef(ctx, org, repo, headSHA, &github.ListCheckRunsOptions{
			CheckName: github.String(name),
			Filter:    github.String("latest"),
		})
		if e != nil || len(result.CheckRuns) == 0 {
			return ""
		}
		return result.CheckRuns[0].GetConclusion()
	}

	sigConclusion := conclusionFor("Team Signature Verification")
	semConclusion := conclusionFor("Semantic Commit Verification")

	// If the PR author is the sole maintainer, the bot auto-approved on their
	// behalf — no separate review is needed.
	maintainerApproved := false
	members, _, listErr := client.Teams.ListTeamMembersBySlug(ctx, org, repo, nil)
	if listErr == nil && len(members) == 1 {
		_, _, authorErr := client.Teams.GetTeamMembershipBySlug(ctx, org, repo, pr.User.GetLogin())
		maintainerApproved = authorErr == nil
	}

	// For multi-maintainer repos, require a human maintainer approval.
	if !maintainerApproved {
		reviews, _, err := client.PullRequests.ListReviews(ctx, org, repo, prNum, nil)
		if err != nil {
			msg := "❌ **Merge Blocked:** Could not retrieve PR review status."
			client.Issues.CreateComment(ctx, org, repo, prNum, &github.IssueComment{Body: &msg})
			return
		}
		for _, review := range reviews {
			if review.GetState() != "APPROVED" {
				continue
			}
			_, _, teamErr := client.Teams.GetTeamMembershipBySlug(ctx, org, repo, review.User.GetLogin())
			if teamErr == nil {
				maintainerApproved = true
				break
			}
		}
	}

	// Sweep all other check runs, paginating until done.
	ownChecks := map[string]bool{
		"Team Signature Verification": true,
		"Team Approval Verification":  true,
		"Semantic Commit Verification": true,
	}
	var failingChecks []string
	page := 1
	for {
		result, _, err := client.Checks.ListCheckRunsForRef(ctx, org, repo, headSHA, &github.ListCheckRunsOptions{
			Filter:      github.String("latest"),
			ListOptions: github.ListOptions{Page: page, PerPage: 100},
		})
		if err != nil {
			break
		}
		for _, run := range result.CheckRuns {
			if ownChecks[run.GetName()] {
				continue
			}
			c := run.GetConclusion()
			if c != "success" && c != "neutral" && c != "skipped" {
				failingChecks = append(failingChecks, fmt.Sprintf("- **%s** is `%s`", run.GetName(), orDefault(c, "pending")))
			}
		}
		if len(result.CheckRuns) < 100 {
			break
		}
		page++
	}

	if sigConclusion != "success" || semConclusion != "success" || !maintainerApproved || len(failingChecks) > 0 {
		var reasons []string
		if sigConclusion != "success" {
			reasons = append(reasons, fmt.Sprintf("- **Team Signature Verification** is `%s`", orDefault(sigConclusion, "pending")))
		}
		if semConclusion != "success" {
			reasons = append(reasons, fmt.Sprintf("- **Semantic Commit Verification** is `%s`", orDefault(semConclusion, "pending")))
		}
		if !maintainerApproved {
			reasons = append(reasons, "- **Team Approval Verification** — no maintainer approval on record")
		}
		reasons = append(reasons, failingChecks...)
		msg := fmt.Sprintf("❌ **Merge Blocked:** The following checks have not passed:\n\n%s", strings.Join(reasons, "\n"))
		client.Issues.CreateComment(ctx, org, repo, prNum, &github.IssueComment{Body: &msg})
		return
	}

	ref := fmt.Sprintf("heads/%s", pr.Base.GetRef())
	sha := headSHA
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
		// Author is a maintainer: only auto-approve if they are the sole maintainer
		members, _, listErr := client.Teams.ListTeamMembersBySlug(ctx, org, repo, nil)
		if listErr == nil && len(members) == 1 {
			body := fmt.Sprintf("🤖 **Auto-Approved:** PR authored by the sole authorized maintainer (@%s).", author)
			client.PullRequests.CreateReview(ctx, org, repo, prNum, &github.PullRequestReviewRequest{
				Event: github.String("APPROVE"),
				Body:  &body,
			})
			client.Checks.CreateCheckRun(ctx, org, repo, github.CreateCheckRunOptions{
				Name:       "Team Approval Verification",
				HeadSHA:    headSHA,
				Status:     github.String("completed"),
				Conclusion: github.String("success"),
				Output: &github.CheckRunOutput{
					Title:   github.String("Maintainer Auto-Approved"),
					Summary: github.String(fmt.Sprintf("PR was auto-approved because the author (@%s) is the sole authorized maintainer.", author)),
				},
			})
		} else {
			client.Checks.CreateCheckRun(ctx, org, repo, github.CreateCheckRunOptions{
				Name:       "Team Approval Verification",
				HeadSHA:    headSHA,
				Status:     github.String("completed"),
				Conclusion: github.String("failure"),
				Output: &github.CheckRunOutput{
					Title:   github.String("Awaiting Maintainer Review"),
					Summary: github.String("This PR requires approval from another authorized maintainer before merging."),
				},
			})
		}
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

	headOwner := e.PullRequest.Head.Repo.Owner.GetLogin()
	headRepo := e.PullRequest.Head.Repo.GetName()

	for _, commit := range commits {
		sha := commit.GetSHA()

		var username string
		if commit.Committer != nil && commit.Committer.GetLogin() != "" {
			username = commit.Committer.GetLogin()
		} else if commit.Author != nil && commit.Author.GetLogin() != "" {
			username = commit.Author.GetLogin()
		}

		if username == "" {
			fmt.Printf("Commit %s has no linked GitHub user\n", sha)
			allValid = false
			break
		}

		keyPath := fmt.Sprintf("%s.txt", username)
		fileContent, _, _, err := client.Repositories.GetContents(ctx, "oreonhq", "team-sigs", keyPath, nil)
		if err != nil || fileContent == nil {
			fmt.Printf("No public key found in oreonhq/team-sigs for user: %s\n", username)
			allValid = false
			break
		}

		asciiKey, _ := fileContent.GetContent()

		valid, err := verifyCommit(ctx, client, headOwner, headRepo, sha, asciiKey)
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
			Name:       "Team Signature Verification",
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

	// -----------------------------------------
	// FEATURE 3: SEMANTIC COMMIT VERIFICATION
	// -----------------------------------------
	semanticRE := regexp.MustCompile(`^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\(.+\))?(!)?: .+`)

	var badCommits []string
	for _, commit := range commits {
		full := commit.Commit.GetMessage()
		parts := strings.SplitN(full, "\n", 2)
		subject := parts[0]
		short := commit.GetSHA()[:7]

		if !semanticRE.MatchString(subject) {
			badCommits = append(badCommits, fmt.Sprintf("- `%s` — not a semantic commit: `%s`", short, subject))
			continue
		}
		if len(subject) > 40 {
			badCommits = append(badCommits, fmt.Sprintf("- `%s` — title too long (%d chars, max 40): `%s`", short, len(subject), subject))
		}
		body := ""
		if len(parts) > 1 {
			body = strings.TrimSpace(parts[1])
		}
		if body == "" {
			badCommits = append(badCommits, fmt.Sprintf("- `%s` — missing commit description", short))
		}
	}

	semConclusion := "success"
	semTitle := "Semantic Commits Verified"
	semSummary := "All commit messages follow the Conventional Commits specification, are within the 40-character title limit, and include a description."
	if len(badCommits) > 0 {
		semConclusion = "failure"
		semTitle = "Commit Message Issues Detected"
		semSummary = fmt.Sprintf("The following commits have issues:\n\n%s\n\nRules: semantic format (`<type>[scope]: <desc>`), title ≤ 40 chars, body required.", strings.Join(badCommits, "\n"))
	}

	client.Checks.CreateCheckRun(ctx, org, repo, github.CreateCheckRunOptions{
		Name:       "Semantic Commit Verification",
		HeadSHA:    headSHA,
		Status:     github.String("completed"),
		Conclusion: github.String(semConclusion),
		Output: &github.CheckRunOutput{
			Title:   github.String(semTitle),
			Summary: github.String(semSummary),
		},
	})
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

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func verifyCommit(ctx context.Context, client *github.Client, owner, repo, commitSHA, asciiPublicKey string) (bool, error) {
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(asciiPublicKey))
	if err != nil {
		return false, fmt.Errorf("err: %v", err)
	}

	gitCommit, _, err := client.Git.GetCommit(ctx, owner, repo, commitSHA)
	if err != nil {
		return false, fmt.Errorf("err: %v", err)
	}

	if gitCommit.Verification == nil || gitCommit.Verification.GetSignature() == "" {
		return false, fmt.Errorf("err: no sig")
	}

	sig := strings.NewReader(gitCommit.Verification.GetSignature())
	payload := strings.NewReader(gitCommit.Verification.GetPayload())

	_, err = openpgp.CheckArmoredDetachedSignature(keyring, payload, sig, nil)
	if err != nil {
		return false, fmt.Errorf("err: %v", err)
	}

	return true, nil
}

func handleRepositoryCreated(ctx context.Context, client *github.Client, e *github.RepositoryEvent) {
	if e.GetAction() != "created" {
		return
	}

	org := e.Repo.Owner.GetLogin()
	repoName := e.Repo.GetName()
	creator := e.Sender.GetLogin()

	// Step 1: Create an org team with the same name as the repo
	team, _, err := client.Teams.CreateTeam(ctx, org, github.NewTeam{Name: repoName, Privacy: github.String("closed")})
	if err != nil {
		log.Printf("Bootstrap: failed to create team %q: %v", repoName, err)
		return
	}
	teamSlug := team.GetSlug()

	// Step 2: Give the team write access
	if _, err = client.Teams.AddTeamRepoBySlug(ctx, org, teamSlug, org, repoName,
		&github.TeamAddTeamRepoOptions{Permission: "push"}); err != nil {
		log.Printf("Bootstrap: failed to grant repo access to team: %v", err)
	}

	// Step 3: Add the creator as a team maintainer
	if _, _, err = client.Teams.AddTeamMembershipBySlug(ctx, org, teamSlug, creator,
		&github.TeamAddTeamMembershipOptions{Role: "maintainer"}); err != nil {
		log.Printf("Bootstrap: failed to add %q to team: %v", creator, err)
	}

	// Fetch the full file tree from oreonhq/default-repo
	defaultInfo, _, err := client.Repositories.Get(ctx, "oreonhq", "default-repo")
	if err != nil {
		log.Printf("Bootstrap: failed to get default-repo: %v", err)
		return
	}
	defaultRef, _, err := client.Git.GetRef(ctx, "oreonhq", "default-repo",
		"refs/heads/"+defaultInfo.GetDefaultBranch())
	if err != nil {
		log.Printf("Bootstrap: failed to get default-repo ref: %v", err)
		return
	}
	defaultTree, _, err := client.Git.GetTree(ctx, "oreonhq", "default-repo",
		defaultRef.Object.GetSHA(), true)
	if err != nil {
		log.Printf("Bootstrap: failed to get default-repo tree: %v", err)
		return
	}

	// Step 5: Apply rules.json as a repository ruleset (directly, not via PR)
	for _, entry := range defaultTree.Entries {
		if entry.GetPath() == "rules.json" && entry.GetType() == "blob" {
			blob, _, blobErr := client.Git.GetBlob(ctx, "oreonhq", "default-repo", entry.GetSHA())
			if blobErr == nil {
				raw, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(blob.GetContent(), "\n", ""))
				applyRuleset(ctx, client, org, repoName, raw)
			}
			break
		}
	}

	// Step 4 & 6: Build tree entries for the bootstrap PR (all files except rules.json)
	hasCodeowners := false
	var prFiles []*github.TreeEntry

	for _, entry := range defaultTree.Entries {
		if entry.GetType() != "blob" || entry.GetPath() == "rules.json" {
			continue
		}
		blob, _, blobErr := client.Git.GetBlob(ctx, "oreonhq", "default-repo", entry.GetSHA())
		if blobErr != nil {
			log.Printf("Bootstrap: failed to get blob %q: %v", entry.GetPath(), blobErr)
			continue
		}
		content := string(func() []byte {
			b, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(blob.GetContent(), "\n", ""))
			return b
		}())
		if entry.GetPath() == ".github/CODEOWNERS" {
			content = fmt.Sprintf("* @%s/%s\n", org, repoName)
			hasCodeowners = true
		}
		prFiles = append(prFiles, &github.TreeEntry{
			Path:    github.String(entry.GetPath()),
			Mode:    github.String("100644"),
			Type:    github.String("blob"),
			Content: github.String(content),
		})
	}

	if !hasCodeowners {
		prFiles = append(prFiles, &github.TreeEntry{
			Path:    github.String(".github/CODEOWNERS"),
			Mode:    github.String("100644"),
			Type:    github.String("blob"),
			Content: github.String(fmt.Sprintf("* @%s/%s\n", org, repoName)),
		})
	}

	// Append license footer to README.md (or create one if absent)
	licenseFooter := "\n## License\nCopyright (C) 2026 Oreon HQ. This program is licensed under GPL-3.0. See [LICENSE](LICENSE).\n"
	readmeIdx := -1
	for i, f := range prFiles {
		if f.GetPath() == "README.md" {
			readmeIdx = i
			break
		}
	}
	if readmeIdx >= 0 {
		prFiles[readmeIdx] = &github.TreeEntry{
			Path:    github.String("README.md"),
			Mode:    github.String("100644"),
			Type:    github.String("blob"),
			Content: github.String(prFiles[readmeIdx].GetContent() + licenseFooter),
		}
	} else {
		prFiles = append(prFiles, &github.TreeEntry{
			Path:    github.String("README.md"),
			Mode:    github.String("100644"),
			Type:    github.String("blob"),
			Content: github.String(fmt.Sprintf("# %s\n", repoName) + licenseFooter),
		})
	}

	// Add the GPL-3.0 license file
	prFiles = append(prFiles, &github.TreeEntry{
		Path:    github.String("LICENSE"),
		Mode:    github.String("100644"),
		Type:    github.String("blob"),
		Content: github.String(gpl3License),
	})

	// Get the new repo's default branch SHA (empty string if repo has no commits)
	newRepo, _, err := client.Repositories.Get(ctx, org, repoName)
	if err != nil {
		log.Printf("Bootstrap: failed to get new repo: %v", err)
		return
	}
	defaultBranch := newRepo.GetDefaultBranch()
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	var baseSHA string
	isEmpty := false
	if baseRef, _, refErr := client.Git.GetRef(ctx, org, repoName, "refs/heads/"+defaultBranch); refErr == nil {
		baseSHA = baseRef.Object.GetSHA()
	} else {
		isEmpty = true
	}

	// GitHub's git trees API rejects requests on a repo with zero objects.
	// Seed a minimal commit via CreateFile so the tree API becomes usable.
	if isEmpty {
		init, _, initErr := client.Repositories.CreateFile(ctx, org, repoName, ".gitkeep",
			&github.RepositoryContentFileOptions{
				Message: github.String("chore: initialize repository"),
				Content: []byte(""),
				Branch:  github.String(defaultBranch),
			})
		if initErr != nil {
			log.Printf("Bootstrap: failed to initialize repo: %v", initErr)
			return
		}
		baseSHA = init.Commit.GetSHA()
	}

	newTree, _, err := client.Git.CreateTree(ctx, org, repoName, baseSHA, prFiles)
	if err != nil {
		log.Printf("Bootstrap: failed to create git tree: %v", err)
		return
	}

	newCommit, _, err := client.Git.CreateCommit(ctx, org, repoName, &github.Commit{
		Message: github.String("chore: bootstrap repository"),
		Tree:    &github.Tree{SHA: github.String(newTree.GetSHA())},
		Parents: []*github.Commit{{SHA: github.String(baseSHA)}},
	})
	if err != nil {
		log.Printf("Bootstrap: failed to create commit: %v", err)
		return
	}

	// For empty repos: push directly to the default branch — no PR needed.
	if isEmpty {
		force := true
		if _, _, err = client.Git.UpdateRef(ctx, org, repoName, &github.Reference{
			Ref:    github.String("refs/heads/" + defaultBranch),
			Object: &github.GitObject{SHA: github.String(newCommit.GetSHA())},
		}, force); err != nil {
			log.Printf("Bootstrap: failed to push bootstrap commit: %v", err)
		}
		return
	}

	bootstrapBranch := "oreon/bootstrap"
	if _, _, err = client.Git.CreateRef(ctx, org, repoName, &github.Reference{
		Ref:    github.String("refs/heads/" + bootstrapBranch),
		Object: &github.GitObject{SHA: github.String(newCommit.GetSHA())},
	}); err != nil {
		log.Printf("Bootstrap: failed to create bootstrap branch: %v", err)
		return
	}

	prBody := fmt.Sprintf(
		"Applies default repository configuration from `oreonhq/default-repo`.\n\n"+
			"- Sets `CODEOWNERS` to `* @%s/%s`\n"+
			"- Applies default templates and configuration\n\n"+
			"Repository ruleset from `rules.json` has already been applied directly.",
		org, repoName,
	)
	if _, _, err = client.PullRequests.Create(ctx, org, repoName, &github.NewPullRequest{
		Title: github.String("chore: bootstrap repository"),
		Body:  github.String(prBody),
		Head:  github.String(bootstrapBranch),
		Base:  github.String(defaultBranch),
	}); err != nil {
		log.Printf("Bootstrap: failed to create PR: %v", err)
	}
}

func applyRuleset(ctx context.Context, client *github.Client, org, repo string, rulesJSON []byte) {
	var ruleset map[string]interface{}
	if err := json.Unmarshal(rulesJSON, &ruleset); err != nil {
		log.Printf("Bootstrap: failed to parse rules.json: %v", err)
		return
	}
	// Strip read-only server fields before POSTing
	for _, field := range []string{"id", "node_id", "created_at", "updated_at", "_links", "source", "source_type"} {
		delete(ruleset, field)
	}
	req, err := client.NewRequest("POST", fmt.Sprintf("repos/%s/%s/rulesets", org, repo), ruleset)
	if err != nil {
		log.Printf("Bootstrap: failed to build ruleset request: %v", err)
		return
	}
	if _, err = client.Do(ctx, req, nil); err != nil {
		log.Printf("Bootstrap: failed to apply ruleset: %v", err)
	}
}
