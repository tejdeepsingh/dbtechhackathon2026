from github import Github


class GitHubClient:

    def __init__(self, github_token: str):
        self.github = Github(github_token)

    def repository_from_url(self, url: str):
        repo = (
            url.replace("https://github.com/", "")
               .replace(".git", "")
        )
        return self.github.get_repo(repo)

    def create_pull_request(
        self,
        repo_url: str,
        title: str,
        body: str,
        head: str,
        base: str,
    ):

        repo = self.repository_from_url(repo_url)

        pr = repo.create_pull(
            title=title,
            body=body,
            head=head,
            base=base,
        )

        return {
            "number": pr.number,
            "url": pr.html_url,
            "state": pr.state,
            "title": pr.title,
        }