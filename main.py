"""
Main entry point for the GitHub Commit Reviewer Workflow.

This module handles the workflow registration and execution.
"""

import os
import json
from typing import Any, Dict

from mistralai.workflows import WorkflowRunner, WorkflowError

from workflows import GitHubCommitReviewer, GitHubWebhookPayload

class GitHubCommitReviewerRunner:
    """Runner for the GitHub Commit Reviewer workflow."""

    def __init__(self):
        self.workflow = GitHubCommitReviewer()
        self.runner = WorkflowRunner()

    async def process_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Process incoming GitHub webhook."""
        try:
            result = self.workflow.process_github_webhook(payload)
            return {
                "status": "success",
                "result": result.dict()
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }

    def run_local_test(self):
        """Run a local test with sample data."""
        sample_payload = {
            "action": "opened",
            "repository": {
                "full_name": "Playyo807/frontend-car-booking-system",
                "name": "frontend-car-booking-system",
                "owner": {"login": "Playyo807"}
            },
            "pull_request": {
                "id": 123456,
                "number": 100,
                "title": "Add new car booking feature",
                "body": "This PR adds a new car booking feature with form validation.",
                "html_url": "https://github.com/Playyo807/frontend-car-booking-system/pull/100",
                "diff_url": "https://github.com/Playyo807/frontend-car-booking-system/pull/100.diff",
                "base": {"ref": "main"},
                "head": {"ref": "feature/car-booking", "sha": "abc123def456"},
                "user": {"login": "Playyo807"}
            },
            "sender": {"login": "Playyo807"}
        }

        print("Running local test with sample PR data...")
        result = self.workflow.process_github_webhook(sample_payload)
        print(f"Test result: {json.dumps(result.dict(), indent=2)}")
        return result

if __name__ == "__main__":
    runner = GitHubCommitReviewerRunner()

    if os.getenv("GITHUB_API_TOKEN") and os.getenv("GITHUB_REPO_OWNER"):
        print("Environment variables configured. Ready for production use.")
    else:
        print("No environment variables found. Running in test mode.")
        runner.run_local_test()