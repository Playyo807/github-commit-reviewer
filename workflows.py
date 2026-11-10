"""
GitHub Commit Reviewer Workflow

A comprehensive workflow that analyzes GitHub commits and pull requests,
performing security vulnerability scanning and logical behavior analysis,
then delivers technical reviews to both GitHub and Slack.
"""

import os
import json
import asyncio
import tempfile
import subprocess
from typing import Any, Dict, List, Optional
from datetime import datetime

import httpx
import requests
from pydantic import BaseModel, Field

from mistralai.workflows import workflow, activity, WorkflowError

# Configuration models
class GitHubConfig(BaseModel):
    repo_owner: str = Field(default="Playyo807")
    repo_name: str = Field(default="frontend-car-booking-system")
    api_token: Optional[str] = None
    base_url: str = "https://api.github.com"

class SlackConfig(BaseModel):
    bot_token: Optional[str] = None
    channel: Optional[str] = None
    base_url: str = "https://slack.com/api"

class AnalysisConfig(BaseModel):
    max_file_size_mb: int = 10
    max_diff_lines: int = 1000
    timeout_seconds: int = 300
    check_security: bool = True
    check_complexity: bool = True
    check_style: bool = True

# Input models
class GitHubWebhookPayload(BaseModel):
    action: str
    repository: Dict[str, Any]
    pull_request: Optional[Dict[str, Any]] = None
    commits: Optional[List[Dict[str, Any]]] = None
    sender: Dict[str, Any]
    installation: Optional[Dict[str, Any]] = None

class CommitInfo(BaseModel):
    sha: str
    message: str
    author: str
    url: str
    diff_url: Optional[str] = None

class PullRequestInfo(BaseModel):
    id: int
    number: int
    title: str
    body: Optional[str] = None
    url: str
    diff_url: str
    base_branch: str
    head_branch: str
    author: str
    commits: List[CommitInfo] = Field(default_factory=list)

# Output models
class SecurityIssue(BaseModel):
    severity: str  # high, medium, low
    type: str
    description: str
    file: str
    line: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: str

class CodeIssue(BaseModel):
    category: str  # complexity, style, logic
    description: str
    file: str
    line: Optional[int] = None
    severity: str = "medium"
    suggestion: str

class ReviewResult(BaseModel):
    overall_score: float  # 0-10
    security_issues: List[SecurityIssue] = Field(default_factory=list)
    code_issues: List[CodeIssue] = Field(default_factory=list)
    strengths: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    summary: str
    analysis_time: float

class DeliveryResult(BaseModel):
    github_posted: bool = False
    slack_posted: bool = False
    github_comment_url: Optional[str] = None
    slack_message_ts: Optional[str] = None
    errors: List[str] = Field(default_factory=list)
    code_issues: List[CodeIssue] = Field(default_factory=list)
    strengths: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    summary: str
    analysis_time: float

class DeliveryResult(BaseModel):
    github_posted: bool = False
    slack_posted: bool = False
    github_comment_url: Optional[str] = None
    slack_message_ts: Optional[str] = None
    errors: List[str] = Field(default_factory=list)

# Activity: Fetch GitHub commit details
@activity
def fetch_commit_details(config: GitHubConfig, commit_sha: str) -> Dict[str, Any]:
    """Fetch detailed information about a specific commit."""
    headers = {
        "Authorization": f"Bearer {config.api_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    url = f"{config.base_url}/repos/{config.repo_owner}/{config.repo_name}/commits/{commit_sha}"
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise WorkflowError(f"Failed to fetch commit details: {str(e)}")

# Activity: Fetch pull request details
@activity
def fetch_pull_request_details(config: GitHubConfig, pr_number: int) -> Dict[str, Any]:
    """Fetch detailed information about a pull request."""
    headers = {
        "Authorization": f"Bearer {config.api_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    url = f"{config.base_url}/repos/{config.repo_owner}/{config.repo_name}/pulls/{pr_number}"
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise WorkflowError(f"Failed to fetch PR details: {str(e)}")

# Activity: Get commit diff
@activity
def get_commit_diff(config: GitHubConfig, commit_sha: str) -> str:
    """Get the diff for a specific commit."""
    headers = {
        "Authorization": f"Bearer {config.api_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    url = f"{config.base_url}/repos/{config.repo_owner}/{config.repo_name}/commits/{commit_sha}"
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        commit_data = response.json()
        
        # Get the diff URL from parents
        if commit_data.get('parents') and len(commit_data['parents']) > 0:
            parent_sha = commit_data['parents'][0]['sha']
            diff_url = f"{config.base_url}/repos/{config.repo_owner}/{config.repo_name}/compare/{parent_sha}...{commit_sha}"
            diff_response = requests.get(diff_url, headers=headers, timeout=30)
            diff_response.raise_for_status()
            return diff_response.text
        
        return ""
    except requests.RequestException as e:
        raise WorkflowError(f"Failed to get commit diff: {str(e)}")

# Activity: Get PR diff
@activity
def get_pr_diff(config: GitHubConfig, pr_number: int) -> str:
    """Get the diff for a pull request."""
    headers = {
        "Authorization": f"Bearer {config.api_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    url = f"{config.base_url}/repos/{config.repo_owner}/{config.repo_name}/pulls/{pr_number}"
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        pr_data = response.json()

        if pr_data.get('diff_url'):
            diff_response = requests.get(pr_data['diff_url'], headers=headers, timeout=30)
            diff_response.raise_for_status()
            return diff_response.text

        return ""
    except requests.RequestException as e:
        raise WorkflowError(f"Failed to get PR diff: {str(e)}")

# Activity: Clone repository temporarily for analysis
@activity
def clone_repository_for_analysis(config: GitHubConfig, commit_sha: Optional[str] = None) -> str:
    """Clone the repository temporarily for code analysis."""
    repo_url = f"https://github.com/{config.repo_owner}/{config.repo_name}.git"

    # Create a temporary directory
    temp_dir = tempfile.mkdtemp(prefix=f"github_review_{config.repo_name}_")

    try:
        # Clone the repository
        cmd = ["git", "clone", repo_url, temp_dir, "--depth", "1"]
        if commit_sha:
            cmd.extend(["--branch", commit_sha])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode != 0:
            raise WorkflowError(f"Failed to clone repository: {result.stderr}")

        # If we need a specific commit, checkout it
        if commit_sha:
            checkout_cmd = ["git", "-C", temp_dir, "checkout", commit_sha]
            checkout_result = subprocess.run(checkout_cmd, capture_output=True, text=True, timeout=30)
            if checkout_result.returncode != 0:
                raise WorkflowError(f"Failed to checkout commit: {checkout_result.stderr}")

        return temp_dir

    except subprocess.TimeoutExpired:
        raise WorkflowError("Repository clone timed out")
    except Exception as e:
        # Clean up temp directory if it exists
        if os.path.exists(temp_dir):
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
        raise WorkflowError(f"Failed to clone repository: {str(e)}")

# Activity: Run security analysis with Bandit
@activity
def run_security_analysis(repo_path: str, file_patterns: List[str] = None) -> List[SecurityIssue]:
    """Run security vulnerability analysis using Bandit."""
    issues = []

    if not file_patterns:
        file_patterns = ["*.py"]

    try:
        # Run Bandit security scan
        cmd = ["bandit", "-r", "-f", "json"]
        for pattern in file_patterns:
            cmd.extend([repo_path, "-p", pattern])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode == 0 and result.stdout:
            try:
                bandit_results = json.loads(result.stdout)

                for result_item in bandit_results.get("results", []):
                    issue = SecurityIssue(
                        severity=result_item.get("issue_confidence", "medium").lower(),
                        type=result_item.get("issue_text", "Unknown"),
                        description=result_item.get("issue_text", ""),
                        file=result_item.get("filename", "unknown").replace(repo_path + "/", ""),
                        line=result_item.get("line_number"),
                        code_snippet=result_item.get("code", ""),
                        recommendation=f"Fix {result_item.get('issue_text', 'this issue')} in {result_item.get('filename', 'the file')}"
                    )
                    issues.append(issue)
            except json.JSONDecodeError:
                pass

    except subprocess.TimeoutExpired:
        issues.append(SecurityIssue(
            severity="medium",
            type="timeout",
            description="Security analysis timed out",
            file="analysis",
            recommendation="Reduce analysis scope or increase timeout"
        ))
    except Exception as e:
        issues.append(SecurityIssue(
            severity="low",
            type="error",
            description=f"Security analysis failed: {str(e)}",
            file="analysis",
            recommendation="Check analysis configuration"
        ))

    return issues

# Activity: Run complexity analysis with Radon
@activity
def run_complexity_analysis(repo_path: str, file_patterns: List[str] = None) -> List[CodeIssue]:
    """Run code complexity analysis using Radon."""
    issues = []

    if not file_patterns:
        file_patterns = ["*.py"]

    try:
        # Run Radon complexity check
        cmd = ["radon", "cc", "-j", "--min", "C"]
        cmd.extend([repo_path])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode == 0 and result.stdout:
            try:
                radon_results = json.loads(result.stdout)

                for file_data in radon_results:
                    filename = file_data.get("name", "unknown").replace(repo_path + "/", "")

                    for func_data in file_data.get("functions", []):
                        complexity = func_data.get("complexity", 0)
                        if complexity > 10:  # High complexity threshold
                            issues.append(CodeIssue(
                                category="complexity",
                                description=f"Function '{func_data.get('name', 'unknown')}' has complexity {complexity}",
                                file=filename,
                                line=func_data.get("line", 1),
                                severity="high" if complexity > 20 else "medium",
                                suggestion=f"Refactor function to reduce complexity below 10"
                            ))
            except json.JSONDecodeError:
                pass

    except subprocess.TimeoutExpired:
        issues.append(CodeIssue(
            category="complexity",
            description="Complexity analysis timed out",
            file="analysis",
            severity="medium",
            suggestion="Reduce analysis scope or increase timeout"
        ))
    except Exception as e:
        issues.append(CodeIssue(
            category="complexity",
            description=f"Complexity analysis failed: {str(e)}",
            file="analysis",
            severity="low",
            suggestion="Check analysis configuration"
        ))

    return issues

# Activity: Run style analysis
@activity
def run_style_analysis(repo_path: str, diff_content: str) -> List[CodeIssue]:
    """Analyze code style and best practices from diff content."""
    issues = []

    # Basic style checks from diff
    lines = diff_content.split('\n')

    for i, line in enumerate(lines):
        if line.startswith('+') and not line.startswith('+++'):
            # Check for common style issues in added lines
            code_line = line[1:]  # Remove the + prefix

            # Check for trailing whitespace
            if code_line.rstrip() != code_line:
                issues.append(CodeIssue(
                    category="style",
                    description="Trailing whitespace",
                    file="diff",
                    line=i + 1,
                    severity="low",
                    suggestion="Remove trailing whitespace"
                ))

            # Check for long lines (assuming 88 char limit)
            if len(code_line) > 88:
                issues.append(CodeIssue(
                    category="style",
                    description=f"Line too long ({len(code_line)} characters)",
                    file="diff",
                    line=i + 1,
                    severity="low",
                    suggestion="Break line into multiple lines"
                ))

            # Check for TODO comments
            if 'TODO' in code_line.upper() or 'FIXME' in code_line.upper():
                issues.append(CodeIssue(
                    category="style",
                    description="TODO/FIXME comment found",
                    file="diff",
                    line=i + 1,
                    severity="medium",
                    suggestion="Address TODO/FIXME or create a proper issue"
                ))

    return issues

# Activity: Analyze logical behavior from diff
@activity
def analyze_logical_behavior(diff_content: str, repo_path: str) -> List[CodeIssue]:
    """Analyze logical behavior and potential issues from code changes."""
    issues = []

    # Look for potential logical issues
    lines = diff_content.split('\n')

    for i, line in enumerate(lines):
        if line.startswith('+') and not line.startswith('+++'):
            code_line = line[1:].strip()

            # Check for potential issues
            if '===' in code_line and ('if' in code_line.lower() or 'while' in code_line.lower()):
                issues.append(CodeIssue(
                    category="logic",
                    description="Potential issue: using == with if/while (should be = for assignment)",
                    file="diff",
                    line=i + 1,
                    severity="high",
                    suggestion="Check if this is a comparison or assignment"
                ))

            # Check for hardcoded credentials
            if any(keyword in code_line.lower() for keyword in ['password', 'secret', 'token', 'key', 'api_key']):
                if ('=' in code_line and ('"' in code_line or "'" in code_line)):
                    issues.append(CodeIssue(
                        category="logic",
                        description="Potential hardcoded credential",
                        file="diff",
                        line=i + 1,
                        severity="high",
                        suggestion="Use environment variables or secrets management"
                    ))

            # Check for empty exception handlers
            if 'except:' in code_line or 'except Exception:' in code_line:
                # Check next few lines for pass or empty block
                next_lines = lines[i+1:i+5]
                if any('pass' in next_line for next_line in next_lines):
                    issues.append(CodeIssue(
                        category="logic",
                        description="Empty exception handler",
                        file="diff",
                        line=i + 1,
                        severity="medium",
                        suggestion="Handle exceptions properly or log them"
                    ))

            # Check for deprecated functions
            deprecated_functions = ['print(', 'input(', 'eval(', 'exec(']
            for func in deprecated_functions:
                if func in code_line:
                    issues.append(CodeIssue(
                        category="logic",
                        description=f"Use of potentially problematic function: {func}",
                        file="diff",
                        line=i + 1,
                        severity="medium",
                        suggestion="Consider safer alternatives"
                    ))

    return issues

# Activity: Generate comprehensive review
@activity
def generate_comprehensive_review(
    security_issues: List[SecurityIssue],
    code_issues: List[CodeIssue],
    diff_content: str,
    pr_info: Optional[PullRequestInfo] = None,
    commit_info: Optional[CommitInfo] = None
) -> ReviewResult:
    """Generate a comprehensive review based on all analysis results."""

    # Calculate overall score
    total_issues = len(security_issues) + len(code_issues)
    high_severity = sum(1 for issue in security_issues if issue.severity == "high") + \
                   sum(1 for issue in code_issues if issue.severity == "high")

    # Base score of 10, subtract for issues
    overall_score = 10.0
    overall_score -= (high_severity * 2)  # High severity issues cost 2 points each
    overall_score -= (total_issues - high_severity)  # Other issues cost 1 point each
    overall_score = max(0, min(10, overall_score))  # Clamp to 0-10
    if self.slack_config.bot_token and self.slack_config.channel:
        slack_success = self.send_slack_review(
            self.slack_config, review_result,
            self.github_config.repo_name, commit_sha=commit_info.sha
        )

    # Clean up temp directory
    import shutil
    if os.path.exists(repo_path):
        shutil.rmtree(repo_path, ignore_errors=True)

    return DeliveryResult(
        github_posted=github_success,
        slack_posted=slack_success,
        errors=[] if (github_success or slack_success) else ["Failed to deliver to any platform"]
    )

except Exception as e:
    # Clean up temp directory if it exists
    if 'repo_path' in locals() and os.path.exists(repo_path):
        import shutil
        shutil.rmtree(repo_path, ignore_errors=True)

    return DeliveryResult(
        github_posted=False,
        slack_posted=False,
        errors=[f"Commit review failed: {str(e)}"]
    )

# Create workflow instance for execution
workflow_instance = GitHubCommitReviewer()