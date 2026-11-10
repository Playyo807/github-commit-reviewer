"""
Worker entry point for the GitHub Commit Reviewer Workflow.

This module handles the Mistral Workflow worker registration and signal handling.
"""

import os
import json
from typing import Any, Dict

from mistralai.workflows import WorkflowRunner, signal, query, update
from mistralai.workflows.worker import Worker

from workflows import GitHubCommitReviewer

# Initialize workflow
workflow_instance = GitHubCommitReviewer()

# Signal handler for GitHub webhook events
@signal
class GitHubWebhookSignal:
    name = "github_webhook"

    async def handler(self, input: Dict[str, Any]) -> Dict[str, Any]:
        """Handle incoming GitHub webhook events."""
        try:
            result = workflow_instance.process_github_webhook(input)
            return {
                "status": "completed",
                "github_posted": result.github_posted,
                "slack_posted": result.slack_posted,
                "errors": result.errors
            }
        except Exception as e:
            return {
                "status": "failed",
                "error": str(e)
            }

# Query handler for checking workflow status
@query
class WorkflowStatusQuery:
    name = "workflow_status"

    async def handler(self) -> Dict[str, Any]:
        """Return the current workflow status."""
        return {
            "status": "active",
            "repo": f"{workflow_instance.github_config.repo_owner}/{workflow_instance.github_config.repo_name}",
            "analysis_config": {
                "check_security": workflow_instance.analysis_config.check_security,
                "check_complexity": workflow_instance.analysis_config.check_complexity,
                "check_style": workflow_instance.analysis_config.check_style
            }
        }

# Update handler for configuration changes
@update
class ConfigurationUpdate:
    name = "update_config"

    async def handler(self, input: Dict[str, Any]) -> Dict[str, Any]:
        """Update workflow configuration."""
        try:
            if "github_config" in input:
                for key, value in input["github_config"].items():
                    setattr(workflow_instance.github_config, key, value)

            if "slack_config" in input:
                for key, value in input["slack_config"].items():
                    setattr(workflow_instance.slack_config, key, value)

            if "analysis_config" in input:
                for key, value in input["analysis_config"].items():
                    setattr(workflow_instance.analysis_config, key, value)

            return {
                "status": "updated",
                "message": "Configuration updated successfully"
            }
        except Exception as e:
            return {
                "status": "failed",
                "error": str(e)
            }

# Create and run the worker
if __name__ == "__main__":
    from mistralai.workflows import Workflow

    class GitHubCommitReviewerWorkflow(Workflow):
        def __init__(self):
            self.workflow = workflow_instance

        @signal
        async def github_webhook(self, input: Dict[str, Any]) -> Dict[str, Any]:
            return await GitHubWebhookSignal().handler(input)

        @query
        async def workflow_status(self) -> Dict[str, Any]:
            return await WorkflowStatusQuery().handler()

        @update
        async def update_config(self, input: Dict[str, Any]) -> Dict[str, Any]:
            return await ConfigurationUpdate().handler(input)

    worker = Worker(
        workflows=[GitHubCommitReviewerWorkflow],
        worker_id="github-commit-reviewer-worker",
        workflow_name="github-commit-reviewer"
    )

    print("Starting GitHub Commit Reviewer Worker...")
    print(f"Monitoring: {workflow_instance.github_config.repo_owner}/{workflow_instance.github_config.repo_name}")

    worker.run()