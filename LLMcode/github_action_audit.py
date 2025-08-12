#!/usr/bin/env python3
"""
Simplified PR Security Audit for GitHub Actions
Runs LLM Code security audit on current working directory and outputs findings to stdout
"""

import os
import sys
import json
import subprocess
import requests
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
import re
import time 

# Import existing components we can reuse
from LLMcode.LLM_call import LLM_call
from LLMcode.prompts import get_security_audit_prompt
from LLMcode.findings_filter import FindingsFilter
from LLMcode.json_parser import parse_json_with_fallbacks
from LLMcode.constants import (
    EXIT_CONFIGURATION_ERROR,
    EXIT_SUCCESS,
    EXIT_GENERAL_ERROR,
    SUBPROCESS_TIMEOUT
)
from LLMcode.logger import get_logger

logger = get_logger(__name__)

class ConfigurationError(ValueError):
    """Raised when configuration is invalid or missing."""
    pass

class AuditError(ValueError):
    """Raised when security audit operations fail."""
    pass

class GitHubActionClient:
    """Simplified GitHub API client for GitHub Actions environment."""
    
    def __init__(self):
        """Initialize GitHub client using environment variables."""
        self.github_token = os.environ.get('GITHUB_TOKEN')
        if not self.github_token:
            raise ValueError("GITHUB_TOKEN environment variable required")
            
        self.headers = {
            'Authorization': f'Bearer {self.github_token}',
            'Accept': 'application/vnd.github.v3+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }
        
        # Get excluded directories from environment
        exclude_dirs = os.environ.get('EXCLUDE_DIRECTORIES', '')
        self.excluded_dirs = [d.strip() for d in exclude_dirs.split(',') if d.strip()] if exclude_dirs else []
        if self.excluded_dirs:
            print(f"[Debug] Excluded directories: {self.excluded_dirs}", file=sys.stderr)
    
    def get_pr_data(self, repo_name: str, pr_number: int) -> Dict[str, Any]:
        """Get PR metadata and files from GitHub API.
        
        Args:
            repo_name: Repository name in format "owner/repo"
            pr_number: Pull request number
            
        Returns:
            Dictionary containing PR data
        """
        # Get PR metadata
        pr_url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
        response = requests.get(pr_url, headers=self.headers)
        response.raise_for_status()
        pr_data = response.json()
        
        # Get PR files with pagination support
        files_url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/files?per_page=100"
        response = requests.get(files_url, headers=self.headers)
        response.raise_for_status()
        files_data = response.json()
        
        return {
            'number': pr_data['number'],
            'title': pr_data['title'],
            'body': pr_data.get('body', ''),
            'user': pr_data['user']['login'],
            'created_at': pr_data['created_at'],
            'updated_at': pr_data['updated_at'],
            'state': pr_data['state'],
            'head': {
                'ref': pr_data['head']['ref'],
                'sha': pr_data['head']['sha'],
                'repo': {
                    'full_name': pr_data['head']['repo']['full_name'] if pr_data['head']['repo'] else repo_name
                }
            },
            'base': {
                'ref': pr_data['base']['ref'],
                'sha': pr_data['base']['sha']
            },
            'files': [
                {
                    'filename': f['filename'],
                    'status': f['status'],
                    'additions': f['additions'],
                    'deletions': f['deletions'],
                    'changes': f['changes'],
                    'patch': f.get('patch', '')
                }
                for f in files_data
                if not self._is_excluded(f['filename'])
            ],
            'additions': pr_data['additions'],
            'deletions': pr_data['deletions'],
            'changed_files': pr_data['changed_files']
        }
    
    def get_pr_diff(self, repo_name: str, pr_number: int) -> str:
        """Get complete PR diff in unified format.
        
        Args:
            repo_name: Repository name in format "owner/repo"
            pr_number: Pull request number
            
        Returns:
            Complete PR diff in unified format
        """
        url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
        headers = dict(self.headers)
        headers['Accept'] = 'application/vnd.github.diff'
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        return self._filter_generated_files(response.text)
    
    def _is_excluded(self, filepath: str) -> bool:
        """Check if a file should be excluded based on directory patterns."""
        for excluded_dir in self.excluded_dirs:
            # Normalize excluded directory (remove leading ./ if present)
            if excluded_dir.startswith('./'):
                normalized_excluded = excluded_dir[2:]
            else:
                normalized_excluded = excluded_dir
            
            # Check if file starts with excluded directory
            if filepath.startswith(excluded_dir + '/'):
                return True
            if filepath.startswith(normalized_excluded + '/'):
                return True
            
            # Check if excluded directory appears anywhere in the path
            if '/' + normalized_excluded + '/' in filepath:
                return True
            
        return False
    
    def _filter_generated_files(self, diff_text: str) -> str:
        """Filter out generated files and excluded directories from diff content."""
        
        file_sections = re.split(r'(?=^diff --git)', diff_text, flags=re.MULTILINE)
        filtered_sections = []
        
        for section in file_sections:
            if not section.strip():
                continue
                
            # Skip generated files
            if ('@generated by' in section or 
                '@generated' in section or 
                'Code generated by OpenAPI Generator' in section or
                'Code generated by protoc-gen-go' in section):
                continue
            
            # Extract filename from diff header
            match = re.match(r'^diff --git a/(.*?) b/', section)
            if match:
                filename = match.group(1)
                if self._is_excluded(filename):
                    print(f"[Debug] Filtering out excluded file: {filename}", file=sys.stderr)
                    continue
            
            filtered_sections.append(section)
        
        return ''.join(filtered_sections)


class SimpleLLMRunner:
    """Simplified LLM runner for GitHub Actions."""
    
    def __init__(self, timeout_minutes: Optional[int] = None):
        """Initialize LLM runner.
        
        Args:
            timeout_minutes: Timeout for LLM execution (defaults to SUBPROCESS_TIMEOUT)
        """
        if timeout_minutes is not None:
            self.timeout_seconds = timeout_minutes * 60
        else:
            self.timeout_seconds = SUBPROCESS_TIMEOUT
    
    

    def run_security_audit(self, repo_dir: Path, prompt: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Run LLM security audit using HTTP API.
        
        Args:
            repo_dir: Path to repository directory
            prompt: Security audit prompt
            
        Returns:
            Tuple of (success, error_message, parsed_results)
        """
        if not repo_dir.exists():
            return False, f"Repository directory does not exist: {repo_dir}", {}
        
        # Check prompt size
        prompt_size = len(prompt.encode('utf-8'))
        if prompt_size > 1024 * 1024:  # 1MB
            print(f"[Warning] Large prompt size: {prompt_size / 1024 / 1024:.2f}MB", file=sys.stderr)
        
        try:
            NUM_RETRIES = 3
            for attempt in range(NUM_RETRIES):
                status_code, response_text = LLM_call(prompt, '')
                
                if status_code != 200:
                    if attempt == NUM_RETRIES - 1:
                        error_details = f"LLM API request failed with status {status_code}\n"
                        error_details += f"Response: {response_text}..."  # First 500 chars
                        return False, error_details, {}
                    else:
                        time.sleep(5*attempt)
                        continue  # Retry
                
                # Check for "Prompt is too long" error
                # if response_data.get('error', {}).get('type') == 'invalid_request_error' and \
                #    'prompt is too long' in response_data.get('error', {}).get('message', '').lower():
                #     return False, "PROMPT_TOO_LONG", {}
                
                # Parse JSON output
                success, parsed_result = parse_json_with_fallbacks(response_text, "LLM API output")
                
                if success:
                    # Extract security findings
                    parsed_results = self._extract_security_findings(parsed_result)
                    return True, "", parsed_results
                else:
                    if attempt == NUM_RETRIES - 1:
                        return False, f"Failed to parse LLM output: {parsed_result[:500]}", {}
                    time.sleep(5*attempt)
                    continue  # Retry
            
        except requests.exceptions.Timeout:
            return False, f"LLM API request timed out after {self.timeout_seconds} seconds", {}
        except Exception as e:
            return False, f"LLM API request failed: {str(e)}", {}
    
    def _extract_security_findings(self, LLM_output: Any) -> Dict[str, Any]:
        """Extract security findings from LLM's JSON response."""
        if isinstance(LLM_output, dict):
            # Only accept LLM Code wrapper with result field
            # Direct format without wrapper is not supported
            if 'result' in LLM_output:
                result_text = LLM_output['result']
                if isinstance(result_text, str):
                    # Try to extract JSON from the result text
                    success, result_json = parse_json_with_fallbacks(result_text, "LLM result text")
                    if success and result_json and 'findings' in result_json:
                        return result_json
        else:
            print("json parse results is actually not json")
        # Return empty structure if no findings found
        return {
            'findings': [],
            'analysis_summary': {
                'files_reviewed': 0,
                'high_severity': 0,
                'medium_severity': 0,
                'low_severity': 0,
                'review_completed': False,
            }
        }
    
    
    
    def validate_LLM_available(self) -> Tuple[bool, str]:
        """Validate that LLM is available via HTTP request."""
        try:
            status_code, response_text = LLM_call('hi', '', 10)
            
            if status_code == 200:
                return True, ""  # LLM is available and properly configured
            else:
                return False, f"LLM API returned status code {status_code}"
                
        except requests.exceptions.Timeout:
            return False, "LLM API request timed out after 10 seconds"
        except requests.exceptions.ConnectionError:
            return False, "Failed to connect to LLM API"
        except Exception as e:
            return False, f"Failed to check LLM API: {str(e)}"




def get_environment_config() -> Tuple[str, int]:
    """Get and validate environment configuration.
    
    Returns:
        Tuple of (repo_name, pr_number)
        
    Raises:
        ConfigurationError: If required environment variables are missing or invalid
    """
    repo_name = os.environ.get('GITHUB_REPOSITORY')
    pr_number_str = os.environ.get('PR_NUMBER')
    
    if not repo_name:
        raise ConfigurationError('GITHUB_REPOSITORY environment variable required')
    
    if not pr_number_str:
        raise ConfigurationError('PR_NUMBER environment variable required')
    
    try:
        pr_number = int(pr_number_str)
    except ValueError:
        raise ConfigurationError(f'Invalid PR_NUMBER: {pr_number_str}')
        
    return repo_name, pr_number


def initialize_clients() -> Tuple[GitHubActionClient, SimpleLLMRunner]:
    """Initialize GitHub and LLM clients.
    
    Returns:
        Tuple of (github_client, llm_runner)
        
    Raises:
        ConfigurationError: If client initialization fails
    """
    try:
        github_client = GitHubActionClient()
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize GitHub client: {str(e)}')
    
    try:
        llm_runner = SimpleLLMRunner()
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize LLM runner: {str(e)}')
        
    return github_client, llm_runner


def initialize_findings_filter(custom_filtering_instructions: Optional[str] = None) -> FindingsFilter:
    """Initialize findings filter based on environment configuration.
    
    Args:
        custom_filtering_instructions: Optional custom filtering instructions
        
    Returns:
        FindingsFilter instance
        
    Raises:
        ConfigurationError: If filter initialization fails
    """
    try:
        # Check if we should use LLM API filtering
        use_LLM_filtering = os.environ.get('ENABLE_LLM_FILTERING', 'false').lower() == 'true'
        api_key = os.environ.get('LLM_API_KEY')
        
        if use_LLM_filtering and api_key:
            # Use full filtering with LLM API
            return FindingsFilter(
                use_hard_exclusions=True,
                use_LLM_filtering=True,
                api_key=api_key,
                custom_filtering_instructions=custom_filtering_instructions
            )
        else:
            # Fallback to filtering with hard rules only
            return FindingsFilter(
                use_hard_exclusions=True,
                use_LLM_filtering=False
            )
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize findings filter: {str(e)}')



def run_security_audit(llm_runner: SimpleLLMRunner, prompt: str) -> Dict[str, Any]:
    """Run the security audit with LLM.
    
    Args:
        llm_runner: LLM runner instance
        prompt: The security audit prompt
        
    Returns:
        Audit results dictionary
        
    Raises:
        AuditError: If the audit fails
    """
    # Get repo directory from environment or use current directory
    repo_path = os.environ.get('REPO_PATH')
    repo_dir = Path(repo_path) if repo_path else Path.cwd()
    success, error_msg, results = llm_runner.run_security_audit(repo_dir, prompt)
    
    if not success:
        raise AuditError(f'Security audit failed: {error_msg}')
        
    return results


def apply_findings_filter(findings_filter, original_findings: List[Dict[str, Any]], 
                         pr_context: Dict[str, Any], github_client: GitHubActionClient) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Apply findings filter to reduce false positives.
    
    Args:
        findings_filter: Filter instance
        original_findings: Original findings from audit
        pr_context: PR context information
        github_client: GitHub client with exclusion logic
        
    Returns:
        Tuple of (kept_findings, excluded_findings, analysis_summary)
    """
    # Apply FindingsFilter
    filter_success, filter_results, filter_stats = findings_filter.filter_findings(
        original_findings, pr_context
    )
    print(f"origin findings are: {original_findings}")
    if filter_success:
        kept_findings = filter_results.get('filtered_findings', [])
        excluded_findings = filter_results.get('excluded_findings', [])
        analysis_summary = filter_results.get('analysis_summary', {})
    else:
        # Filtering failed, keep all findings
        kept_findings = original_findings
        excluded_findings = []
        analysis_summary = {}
    
    # Apply final directory exclusion filtering
    final_kept_findings = []
    directory_excluded_findings = []
    
    for finding in kept_findings:
        if _is_finding_in_excluded_directory(finding, github_client):
            directory_excluded_findings.append(finding)
        else:
            final_kept_findings.append(finding)
    
    # Update excluded findings list
    all_excluded_findings = excluded_findings + directory_excluded_findings
    
    # Update analysis summary with directory filtering stats
    analysis_summary['directory_excluded_count'] = len(directory_excluded_findings)
    
    return final_kept_findings, all_excluded_findings, analysis_summary


def _is_finding_in_excluded_directory(finding: Dict[str, Any], github_client: GitHubActionClient) -> bool:
    """Check if a finding references a file in an excluded directory.
    
    Args:
        finding: Security finding dictionary
        github_client: GitHub client with exclusion logic
        
    Returns:
        True if finding should be excluded, False otherwise
    """
    file_path = finding.get('file', '')
    if not file_path:
        return False
    
    return github_client._is_excluded(file_path)


def main():
    """Main execution function for GitHub Action."""
    try:
        # Get environment configuration
        try:
            repo_name, pr_number = get_environment_config()
        except ConfigurationError as e:
            print(json.dumps({'error': str(e)}))
            sys.exit(EXIT_CONFIGURATION_ERROR)
        
        # Load custom filtering instructions if provided
        custom_filtering_instructions = None
        filtering_file = os.environ.get('FALSE_POSITIVE_FILTERING_INSTRUCTIONS', '')
        if filtering_file and Path(filtering_file).exists():
            try:
                with open(filtering_file, 'r', encoding='utf-8') as f:
                    custom_filtering_instructions = f.read()
                    logger.info(f"Loaded custom filtering instructions from {filtering_file}")
            except Exception as e:
                logger.warning(f"Failed to read filtering instructions file {filtering_file}: {e}")
        
        # Load custom security scan instructions if provided
        custom_scan_instructions = None
        scan_file = os.environ.get('CUSTOM_SECURITY_SCAN_INSTRUCTIONS', '')
        if scan_file and Path(scan_file).exists():
            try:
                with open(scan_file, 'r', encoding='utf-8') as f:
                    custom_scan_instructions = f.read()
                    logger.info(f"Loaded custom security scan instructions from {scan_file}")
            except Exception as e:
                logger.warning(f"Failed to read security scan instructions file {scan_file}: {e}")
        
        # Initialize components
        try:
            github_client, llm_runner = initialize_clients()
        except ConfigurationError as e:
            print(json.dumps({'error': str(e)}))
            sys.exit(EXIT_CONFIGURATION_ERROR)
            
        # Initialize findings filter
        try:
            findings_filter = initialize_findings_filter(custom_filtering_instructions)
        except ConfigurationError as e:
            print(json.dumps({'error': str(e)}))
            sys.exit(EXIT_CONFIGURATION_ERROR)
        
        # Validate LLM is available
        llm_ok, llm_error = llm_runner.validate_LLM_available()
        if not llm_ok:
            print(json.dumps({'error': f'LLM not available: {llm_error}'}))
            sys.exit(EXIT_GENERAL_ERROR)
        
        # Get PR data
        try:
            pr_data = github_client.get_pr_data(repo_name, pr_number)
            pr_diff = github_client.get_pr_diff(repo_name, pr_number)
        except Exception as e:
            print(json.dumps({'error': f'Failed to fetch PR data: {str(e)}'}))
            sys.exit(EXIT_GENERAL_ERROR)
                
        # Generate security audit prompt
        prompt = get_security_audit_prompt(pr_data, pr_diff, custom_scan_instructions=custom_scan_instructions)
        
        # Run LLM security audit
        # Get repo directory from environment or use current directory
        repo_path = os.environ.get('REPO_PATH')
        repo_dir = Path(repo_path) if repo_path else Path.cwd()
        success, error_msg, results = llm_runner.run_security_audit(repo_dir, prompt)
        print(f"run_security_audit exec results: success: {success}, error_msg: {error_msg}, results: {results}")
        # If prompt is too long, retry without diff
        if not success and error_msg == "PROMPT_TOO_LONG":
            print(f"[Info] Prompt too long, retrying without diff. Original prompt length: {len(prompt)} characters", file=sys.stderr)
            prompt_without_diff = get_security_audit_prompt(pr_data, pr_diff, include_diff=False, custom_scan_instructions=custom_scan_instructions)
            print(f"[Info] New prompt length: {len(prompt_without_diff)} characters", file=sys.stderr)
            success, error_msg, results = llm_runner.run_security_audit(repo_dir, prompt_without_diff)
        
        if not success:
            print(json.dumps({'error': f'Security audit failed: {error_msg}'}))
            sys.exit(EXIT_GENERAL_ERROR)
        
        print(f"origin findings from results: {results}")
        # Filter findings to reduce false positives
        original_findings = results.get('findings', [])
        
        # Prepare PR context for better filtering
        pr_context = {
            'repo_name': repo_name,
            'pr_number': pr_number,
            'title': pr_data.get('title', ''),
            'description': pr_data.get('body', '')
        }
        
        # Apply findings filter (including final directory exclusion)
        kept_findings, excluded_findings, analysis_summary = apply_findings_filter(
            findings_filter, original_findings, pr_context, github_client
        )
        
        # Prepare output
        output = {
            'pr_number': pr_number,
            'repo': repo_name,
            'findings': kept_findings,
            'analysis_summary': results.get('analysis_summary', {}),
            'filtering_summary': {
                'total_original_findings': len(original_findings),
                'excluded_findings': len(excluded_findings),
                'kept_findings': len(kept_findings),
                'filter_analysis': analysis_summary,
                'excluded_findings_details': excluded_findings  # Include full details of what was filtered
            }
        }
        
        # Output JSON to stdout
        print(json.dumps(output, indent=2))
        
        # Exit with appropriate code
        high_severity_count = len([f for f in kept_findings if f.get('severity', '').upper() == 'HIGH'])
        sys.exit(EXIT_GENERAL_ERROR if high_severity_count > 0 else EXIT_SUCCESS)
        
    except Exception as e:
        print(json.dumps({'error': f'Unexpected error: {str(e)}'}))
        sys.exit(EXIT_CONFIGURATION_ERROR)


if __name__ == '__main__':
    main()
