import traceback

from flask import Blueprint
from flask import jsonify
from flask import request

from change_processor import ChangeProcessor
from git_manager import GitManager
from github_client import GitHubClient
from models import ChangeRequest
from models import PullRequestResponse

from pathlib import Path

pr_blueprint = Blueprint(
    "pr",
    __name__,
    url_prefix="/pipelinelinttool"
)


@pr_blueprint.route("/health", methods=["GET"])
def health():
    return jsonify(
        {
            "status": "UP"
        }
    )


@pr_blueprint.route("/pull-request", methods=["POST"])
def create_pull_request():

    try:

        body = request.get_json()

        if body is None:
            return jsonify(
                {
                    "error": "Request body missing"
                }
            ), 400

        request_model = ChangeRequest.model_validate(body)

        git = GitManager(request_model.workspace)

        repo = git.clone(request_model.repo)

        git.checkout_branch(
            repo,
            request_model.base_branch,
            request_model.new_branch,
        )

        processor = ChangeProcessor(
            Path(repo.working_tree_dir)
        )

        processor.apply(request_model)

        git.commit(
            repo,
            request_model.commit_message,
        )

        sha = git.push(
            repo,
            request_model.new_branch,
        )

        github = GitHubClient(request_model.github_token)

        pr = github.create_pull_request(
            repo_url=request_model.repo,
            title=request_model.pr_title,
            body=request_model.pr_body,
            head=request_model.new_branch,
            base=request_model.base_branch,
        )

        response = PullRequestResponse(
            success=True,
            number=pr["number"],
            url=pr["url"],
            branch=request_model.new_branch,
            sha=sha,
        )

        return jsonify(
            response.model_dump()
        )

    except Exception as ex:

        return (
            jsonify(
                {
                    "success": False,
                    "error": str(ex),
                    "trace": traceback.format_exc(),
                }
            ),
            500,
        )