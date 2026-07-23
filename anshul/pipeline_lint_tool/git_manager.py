from pathlib import Path

from git import Repo


class GitManager:

    def __init__(self, workspace: str):
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)

    def clone(self, repo_url: str):

        repo_name = repo_url.split("/")[-1].replace(".git", "")

        target = self.workspace / repo_name

        if target.exists():
            Repo(target).git.fetch("--all")
            return Repo(target)

        return Repo.clone_from(repo_url, target)

    def checkout_branch(self, repo: Repo, base_branch: str, new_branch: str):

        repo.git.checkout(base_branch)

        repo.git.pull()

        repo.git.checkout("-B", new_branch)

    def commit(self, repo: Repo, message: str):

        repo.git.add(A=True)

        if repo.is_dirty(untracked_files=True):
            repo.index.commit(message)

    def push(self, repo: Repo, branch: str):

        origin = repo.remote(name="origin")

        origin.push(refspec=f"{branch}:{branch}")

        sha = repo.head.commit.hexsha

        return sha