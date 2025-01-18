import os
import subprocess
from github import Github


def read_branch_order(filename=".github/scripts/branch-order.txt"):
    with open(filename, "r") as f:
        return [
            line.strip()
            for line in f
            if (line.strip() and not line.strip().startswith("#"))
        ]


def get_current_branch(pr_number):
    g = Github(os.environ["GITHUB_TOKEN"])
    repo = g.get_repo(os.environ["REPO"])
    pr = repo.get_pull(int(pr_number))
    return pr.base.ref


def get_child_branches(current_branch, branches):
    try:
        current_index = branches.index(current_branch)
        return branches[:current_index]
    except ValueError:
        return []


def cherry_pick_to_branch(commit_sha, target_branch):
    try:
        # Fetch and checkout target branch
        subprocess.run(["git", "fetch", "origin", target_branch], check=True)
        subprocess.run(["git", "checkout", target_branch], check=True)

        # Cherry-pick the commit
        result = subprocess.run(
            ["git", "cherry-pick", "-m", "1", commit_sha],
            capture_output=True,
            text=True,
        )
        print(result.stderr)

        if result.returncode == 0:
            # Push the changes
            subprocess.run(
                ["git", "push", "origin", target_branch],
                check=True
            )
            return True
        else:
            # If there's a conflict, abort the cherry-pick
            subprocess.run(["git", "cherry-pick", "--abort"])
            return False
    except subprocess.CalledProcessError:
        return False


def main():
    # Get PR number from environment
    pr_number = os.environ["PR_NUMBER"]

    # Initialize GitHub client
    g = Github(os.environ["GITHUB_TOKEN"])
    repo = g.get_repo(os.environ["REPO"])
    pr = repo.get_pull(int(pr_number))

    # Check if the PR is merged
    if not pr.merged:
        print("❌ PR is not yet merged.")
        return

    # Get the merge commit SHA
    merge_commit_sha = pr.merge_commit_sha
    if not merge_commit_sha:
        print("No merge commit found")
        return
    print(f"merge_commit_sha: {merge_commit_sha}")

    # Read branch order
    branches = read_branch_order()

    # Get current branch and find children
    current_branch = get_current_branch(pr_number)
    child_branches = get_child_branches(current_branch, branches)

    if len(child_branches) == 0:
        pr.create_issue_comment(
            "💤 No target branches found. Cherry-pick skipped."
        )
        return

    # Cherry-pick to each child branch
    failed_branches = []
    for branch in child_branches:
        success = cherry_pick_to_branch(merge_commit_sha, branch)
        if not success:
            failed_branches.append(branch)

    if len(failed_branches) == 0:
        pr.create_issue_comment(
            f"✅ Successfully cherry-picked to {len(child_branches)} branches."
        )
    else:
        pr.create_issue_comment(
            "❌ Cherry-pick failed for the following branches "
            "(manual intervention required):\n" +
            "\n".join([f"- {branch}" for branch in failed_branches])
        )


if __name__ == "__main__":
    main()
