#!/usr/bin/env python3
"""
GitHub Commit Reviewer - Standalone Version

A standalone script that can analyze GitHub commits and pull requests,
perform security vulnerability scanning and logical behavior analysis.

Usage:
    python commit_reviewer.py --repo owner/repo --pr 123
    python commit_reviewer.py --repo owner/repo --commit abc123
    python commit_reviewer.py --local /path/to/code
"""

import os
import sys
import json
import argparse
import tempfile
import subprocess
from typing import List, Dict, Any, Optional
from datetime import datetime
import requests

class CodeReviewer:
    """Main code reviewer class."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.github_token = self.config.get('github_token') or os.getenv('GITHUB_API_TOKEN')
        self.slack_token = self.config.get('slack_token') or os.getenv('SLACK_BOT_TOKEN')
        self.slack_channel = self.config.get('slack_channel') or os.getenv('SLACK_CHANNEL')

        # Analysis configuration
        self.max_file_size = int(self.config.get('max_file_size_mb', 10)) * 1024 * 1024
        self.max_diff_lines = int(self.config.get('max_diff_lines', 1000))
        self.timeout = int(self.config.get('timeout_seconds', 300))

    def analyze_repository(self, repo_path: str, diff_content: str = "") -> Dict[str, Any]:
        """Analyze a repository for code quality issues."""
        start_time = datetime.now()

        results = {
            'security_issues': [],
            'code_issues': [],
            'strengths': [],
            'recommendations': [],
            'score': 10.0,
            'analysis_time': 0.0,
            'files_analyzed': 0,
            'lines_analyzed': 0
        }

        try:
            # Run security analysis
            security_issues = self._run_security_analysis(repo_path)
            results['security_issues'] = security_issues

            # Run complexity analysis
            complexity_issues = self._run_complexity_analysis(repo_path)
            results['code_issues'].extend(complexity_issues)

            # Run style analysis on diff
            if diff_content:
                style_issues = self._analyze_diff_style(diff_content)
                results['code_issues'].extend(style_issues)

            # Run logical analysis on diff
            if diff_content:
                logic_issues = self._analyze_logical_behavior(diff_content)
                results['code_issues'].extend(logic_issues)

            # Generate strengths and recommendations
            self._generate_insights(results)

            # Calculate score
            results['score'] = self._calculate_score(results)

            # Calculate analysis time
            end_time = datetime.now()
            results['analysis_time'] = (end_time - start_time).total_seconds()

        except Exception as e:
            results['error'] = str(e)
            results['score'] = 0.0

        return results

    def _run_security_analysis(self, repo_path: str) -> List[Dict[str, Any]]:
        """Run security analysis using Bandit."""
        issues = []

        try:
            bandit_available = self._check_command_available('bandit')
            if not bandit_available:
                return [{
                    'type': 'security',
                    'severity': 'medium',
                    'description': 'Bandit not available for security analysis',
                    'file': 'analysis',
                    'recommendation': 'Install bandit: pip install bandit'
                }]

            cmd = ['bandit', '-r', '-f', 'json', repo_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)

            if result.returncode == 0 and result.stdout:
                try:
                    bandit_results = json.loads(result.stdout)
                    for item in bandit_results.get('results', []):
                        issues.append({
                            'type': 'security',
                            'severity': item.get('issue_confidence', 'medium').lower(),
                            'description': item.get('issue_text', 'Unknown security issue'),
                            'file': item.get('filename', 'unknown').replace(repo_path + '/', ''),
                            'line': item.get('line_number'),
                            'code_snippet': item.get('code', ''),
                            'recommendation': f"Fix {item.get('issue_text', 'this issue')}"
                        })
                except json.JSONDecodeError:
                    pass

        except subprocess.TimeoutExpired:
            issues.append({
                'type': 'security',
                'severity': 'medium',
                'description': 'Security analysis timed out',
                'file': 'analysis',
                'recommendation': 'Reduce analysis scope or increase timeout'
            })
        except Exception as e:
            issues.append({
                'type': 'security',
                'severity': 'low',
                'description': f'Security analysis failed: {str(e)}',
                'file': 'analysis',
                'recommendation': 'Check analysis configuration'
            })

        return issues

    def _run_complexity_analysis(self, repo_path: str) -> List[Dict[str, Any]]:
        """Run complexity analysis using Radon."""
        issues = []

        try:
            radon_available = self._check_command_available('radon')
            if not radon_available:
                return [{
                    'type': 'complexity',
                    'severity': 'medium',
                    'description': 'Radon not available for complexity analysis',
                    'file': 'analysis',
                    'recommendation': 'Install radon: pip install radon'
                }]

            cmd = ['radon', 'cc', '-j', '--min', 'C', repo_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout // 2)

            if result.returncode == 0 and result.stdout:
                try:
                    radon_results = json.loads(result.stdout)
                    for file_data in radon_results:
                        filename = file_data.get('name', 'unknown').replace(repo_path + '/', '')
                        for func_data in file_data.get('functions', []):
                            complexity = func_data.get('complexity', 0)
                            if complexity > 10:
                                issues.append({
                                    'type': 'complexity',
                                    'severity': 'high' if complexity > 20 else 'medium',
                                    'description': f"Function '{func_data.get('name', 'unknown')}' has complexity {complexity}",
                                    'file': filename,
                                    'line': func_data.get('line', 1),
                                    'recommendation': 'Refactor function to reduce complexity below 10'
                                })
                except json.JSONDecodeError:
                    pass

        except subprocess.TimeoutExpired:
            issues.append({
                'type': 'complexity',
                'severity': 'medium',
                'description': 'Complexity analysis timed out',
                'file': 'analysis',
                'recommendation': 'Reduce analysis scope or increase timeout'
            })
        except Exception as e:
            issues.append({
                'type': 'complexity',
                'severity': 'low',
                'description': f'Complexity analysis failed: {str(e)}',
                'file': 'analysis',
                'recommendation': 'Check analysis configuration'
            })

        return issues

    def _analyze_diff_style(self, diff_content: str) -> List[Dict[str, Any]]:
        """Analyze code style from diff content."""
        issues = []
        lines = diff_content.split('\n')

        for i, line in enumerate(lines):
            if line.startswith('+') and not line.startswith('+++'):
                code_line = line[1:]

                if code_line.rstrip() != code_line:
                    issues.append({
                        'type': 'style',
                        'severity': 'low',
                        'description': 'Trailing whitespace',
                        'file': 'diff',
                        'line': i + 1,
                        'recommendation': 'Remove trailing whitespace'
                    })

                if len(code_line) > 88:
                    issues.append({
                        'type': 'style',
                        'severity': 'low',
                        'description': f'Line too long ({len(code_line)} characters)',
                        'file': 'diff',
                        'line': i + 1,
                        'recommendation': 'Break line into multiple lines'
                    })

                if 'TODO' in code_line.upper() or 'FIXME' in code_line.upper():
                    issues.append({
                        'type': 'style',
                        'severity': 'medium',
                        'description': 'TODO/FIXME comment found',
                        'file': 'diff',
                        'line': i + 1,
                        'recommendation': 'Address TODO/FIXME or create a proper issue'
                    })

        return issues

    def _analyze_logical_behavior(self, diff_content: str) -> List[Dict[str, Any]]:
        """Analyze logical behavior from diff content."""
        issues = []
        lines = diff_content.split('\n')

        for i, line in enumerate(lines):
            if line.startswith('+') and not line.startswith('+++'):
                code_line = line[1:].strip()

                if '===' in code_line and ('if' in code_line.lower() or 'while' in code_line.lower()):
                    issues.append({
                        'type': 'logic',
                        'severity': 'high',
                        'description': 'Potential issue: using == with if/while (should be = for assignment)',
                        'file': 'diff',
                        'line': i + 1,
                        'recommendation': 'Check if this is a comparison or assignment'
                    })

                if any(keyword in code_line.lower() for keyword in ['password', 'secret', 'token', 'key', 'api_key']):
                    if ('=' in code_line and ('"' in code_line or "'" in code_line)):
                        issues.append({
                            'type': 'logic',
                            'severity': 'high',
                            'description': 'Potential hardcoded credential',
                            'file': 'diff',
                            'line': i + 1,
                            'recommendation': 'Use environment variables or secrets management'
                        })

                if 'except:' in code_line or 'except Exception:' in code_line:
                    next_lines = lines[i+1:i+5]
                    if any('pass' in next_line for next_line in next_lines):
                        issues.append({
                            'type': 'logic',
                            'severity': 'medium',
                            'description': 'Empty exception handler',
                            'file': 'diff',
                            'line': i + 1,
                            'recommendation': 'Handle exceptions properly or log them'
                        })

                deprecated_functions = ['print(', 'input(', 'eval(', 'exec(']
                for func in deprecated_functions:
                    if func in code_line:
                        issues.append({
                            'type': 'logic',
                            'severity': 'medium',
                            'description': f'Use of potentially problematic function: {func}',
                            'file': 'diff',
                            'line': i + 1,
                            'recommendation': 'Consider safer alternatives'
                        })

        return issues

    def _generate_insights(self, results: Dict[str, Any]):
        """Generate strengths and recommendations from analysis results."""
        total_issues = len(results['security_issues']) + len(results['code_issues'])

        if total_issues == 0:
            results['strengths'].extend([
                'No security vulnerabilities detected',
                'Clean code with no style issues',
                'Good complexity management'
            ])
        else:
            if len(results['security_issues']) == 0:
                results['strengths'].append('No security vulnerabilities detected')
            if len([issue for issue in results['code_issues'] if issue['type'] == 'complexity']) == 0:
                results['strengths'].append('Good complexity management')

        high_security = [issue for issue in results['security_issues'] if issue['severity'] == 'high']
        if high_security:
            results['recommendations'].append(f"Address {len(high_security)} high-severity security issues immediately")

        medium_security = [issue for issue in results['security_issues'] if issue['severity'] == 'medium']
        if medium_security:
            results['recommendations'].append(f"Review {len(medium_security)} medium-severity security issues")

        high_complexity = [issue for issue in results['code_issues'] if issue['type'] == 'complexity' and issue['severity'] == 'high']
        if high_complexity:
            results['recommendations'].append(f"Refactor {len(high_complexity)} functions with high complexity")

    def _calculate_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall score from analysis results."""
        total_issues = len(results['security_issues']) + len(results['code_issues'])
        high_severity = sum(1 for issue in results['security_issues'] if issue['severity'] == 'high') + \
                       sum(1 for issue in results['code_issues'] if issue['severity'] == 'high')

        score = 10.0
        score -= (high_severity * 2)
        score -= (total_issues - high_severity)
        score = max(0, min(10, score))

        return round(score, 1)

    def _check_command_available(self, command: str) -> bool:
        """Check if a command is available."""
        try:
            result = subprocess.run(['which', command], capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def format_review_report(self, results: Dict[str, Any], pr_info: Dict[str, Any] = None) -> str:
        """Format the review results as a markdown report."""
        report = "## 🔍 Code Review Report\n\n"
        report += f"**Overall Score: {results['score']}/10**\n\n"

        if results.get('strengths'):
            report += "### ✅ Strengths\n"
            for strength in results['strengths'][:5]:
                report += f"- {strength}\n"
            report += "\n"

        if results.get('security_issues'):
            report += "### 🚨 Security Issues\n"
            for issue in sorted(results['security_issues'], key=lambda x: x['severity'], reverse=True):
                severity_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(issue['severity'], "⚪")
                report += f"{severity_emoji} **{issue['type']}** in `{issue['file']}`"
                if issue.get('line'):
                    report += f" (line {issue['line']})"
                report += f"\n"
                report += f"   - {issue['description']}\n"
                report += f"   - 💡 *{issue['recommendation']}*\n"
            report += "\n"

        if results.get('code_issues'):
            report += "### 🔧 Code Issues\n"
            for issue in sorted(results['code_issues'], key=lambda x: x['severity'], reverse=True):
                severity_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(issue['severity'], "⚪")
                report += f"{severity_emoji} **{issue['type']}** in `{issue['file']}`"
                if issue.get('line'):
                    report += f" (line {issue['line']})"
                report += f"\n"
                report += f"   - {issue['description']}\n"
                report += f"   - 💡 *{issue['suggestion'] if 'suggestion' in issue else issue['recommendation']}*\n"
            report += "\n"

        if results.get('recommendations'):
            report += "### 📋 Recommendations\n"
            for rec in results['recommendations'][:5]:
                report += f"- {rec}\n"
            report += "\n"

        report += f"*Analysis Time: {results['analysis_time']:.2f} seconds*\n"

        if pr_info:
            report += f"*PR: [{pr_info.get('title', 'Untitled')}](#{pr_info.get('number', '')})*\n"

        return report

    def fetch_github_pr(self, owner: str, repo: str, pr_number: int) -> Dict[str, Any]:
        """Fetch GitHub pull request details."""
        if not self.github_token:
            raise Exception("GitHub token required")

        headers = {
            "Authorization": f"Bearer {self.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()

    def get_pr_diff(self, owner: str, repo: str, pr_number: int) -> str:
        """Get pull request diff."""
        if not self.github_token:
            raise Exception("GitHub token required")

        headers = {
            "Authorization": f"Bearer {self.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        pr_data = self.fetch_github_pr(owner, repo, pr_number)
        if pr_data.get('diff_url'):
            response = requests.get(pr_data['diff_url'], headers=headers, timeout=30)
            response.raise_for_status()
            return response.text
        return ""

    def clone_repository(self, repo_url: str, target_dir: str = None, commit_sha: str = None) -> str:
        """Clone a GitHub repository."""
        if target_dir is None:
            target_dir = tempfile.mkdtemp(prefix="github_review_")

        cmd = ['git', 'clone', repo_url, target_dir, '--depth', '1']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode != 0:
            raise Exception(f"Failed to clone repository: {result.stderr}")

        if commit_sha:
            checkout_cmd = ['git', '-C', target_dir, 'checkout', commit_sha]
            checkout_result = subprocess.run(checkout_cmd, capture_output=True, text=True, timeout=30)
            if checkout_result.returncode != 0:
                raise Exception(f"Failed to checkout commit: {checkout_result.stderr}")

        return target_dir

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='GitHub Commit Reviewer')
    parser.add_argument('--repo', help='GitHub repository (owner/repo)')
    parser.add_argument('--pr', type=int, help='Pull request number')
    parser.add_argument('--commit', help='Commit SHA')
    parser.add_argument('--local', help='Local directory to analyze')
    parser.add_argument('--output', help='Output file for report')
    parser.add_argument('--github-token', help='GitHub API token')
    parser.add_argument('--slack-token', help='Slack bot token')
    parser.add_argument('--slack-channel', help='Slack channel')
    parser.add_argument('--post-github', action='store_true', help='Post review to GitHub')
    parser.add_argument('--post-slack', action='store_true', help='Post review to Slack')

    args = parser.parse_args()

    config = {}
    if args.github_token:
        config['github_token'] = args.github_token
    if args.slack_token:
        config['slack_token'] = args.slack_token
    if args.slack_channel:
        config['slack_channel'] = args.slack_channel

    reviewer = CodeReviewer(config)

    try:
        results = None
        pr_info = None

        if args.local:
            print(f"Analyzing local directory: {args.local}")
            results = reviewer.analyze_repository(args.local)

        elif args.repo and args.pr:
            owner, repo = args.repo.split('/')
            print(f"Fetching PR #{args.pr} from {args.repo}")
            pr_data = reviewer.fetch_github_pr(owner, repo, args.pr)
            pr_info = {
                'number': args.pr,
                'title': pr_data.get('title', ''),
                'url': pr_data.get('html_url', '')
            }

            print(f"Cloning repository...")
            repo_url = f"https://github.com/{owner}/{repo}.git"
            temp_dir = reviewer.clone_repository(repo_url, commit_sha=pr_data.get('head', {}).get('sha'))

            print(f"Getting diff...")
            diff_content = reviewer.get_pr_diff(owner, repo, args.pr)

            print(f"Analyzing code...")
            results = reviewer.analyze_repository(temp_dir, diff_content)

            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

        elif args.repo and args.commit:
            owner, repo = args.repo.split('/')
            print(f"Fetching commit {args.commit} from {args.repo}")
            commit_data = reviewer.fetch_github_commit(owner, repo, args.commit)

            print(f"Cloning repository...")
            repo_url = f"https://github.com/{owner}/{repo}.git"
            temp_dir = reviewer.clone_repository(repo_url, commit_sha=args.commit)

            print(f"Getting diff...")
            diff_content = reviewer.get_commit_diff(owner, repo, args.commit)

            print(f"Analyzing code...")
            results = reviewer.analyze_repository(temp_dir, diff_content)

            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
        else:
            parser.print_help()
            return 1

        report = reviewer.format_review_report(results, pr_info)
        print("\n" + report)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"\nReport saved to: {args.output}")

        if args.post_github and args.repo and args.pr:
            owner, repo = args.repo.split('/')
            success = reviewer.post_github_comment(owner, repo, args.pr, report)
            if success:
                print(f"\n✅ Review posted to GitHub PR #{args.pr}")
            else:
                print(f"\n❌ Failed to post review to GitHub")

        if args.post_slack:
            slack_text = f"🔍 Code Review: {pr_info.get('title', 'Commit') if pr_info else args.commit[:7] if args.commit else 'Analysis'}\n"
            slack_text += f"Score: {results['score']}/10\n"
            slack_text += f"Security Issues: {len(results.get('security_issues', []))}\n"
            slack_text += f"Code Issues: {len(results.get('code_issues', []))}"

            success = reviewer.send_slack_message(slack_text)
            if success:
                print(f"\n✅ Review posted to Slack")
            else:
                print(f"\n❌ Failed to post review to Slack")

        return 0

    except Exception as e:
        print(f"\n❌ Error: {str(e)}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())