class PRAutomationError(Exception):
    pass


class ValidationError(PRAutomationError):
    pass


class GitError(PRAutomationError):
    pass


class GitHubError(PRAutomationError):
    pass