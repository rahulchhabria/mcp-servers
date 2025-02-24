import asyncio
from dataclasses import dataclass
from urllib.parse import urlparse

import click
import httpx
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from mcp.shared.exceptions import McpError
import mcp.server.stdio

SENTRY_API_BASE = "https://sentry.io/api/0/"
MISSING_AUTH_TOKEN_MESSAGE = (
    """Sentry authentication token not found. Please specify your Sentry auth token."""
)


@dataclass
class SentryTraceData:
    trace_id: str
    transaction: str
    project_id: str
    timestamp: str
    duration: float
    status: str
    spans: list[dict]
    tags: dict
    
    def to_text(self) -> str:
        spans_text = "\n".join([
            f"  - {span.get('op', 'unknown')}: {span.get('description', 'N/A')} ({span.get('duration', 0)}ms)"
            for span in self.spans
        ])
        
        tags_text = "\n".join([
            f"  {key}: {value}"
            for key, value in self.tags.items()
        ])
        
        return f"""
Sentry Performance Trace:
ID: {self.trace_id}
Transaction: {self.transaction}
Project: {self.project_id}
Timestamp: {self.timestamp}
Duration: {self.duration}ms
Status: {self.status}

Spans:
{spans_text}

Tags:
{tags_text}
        """
    
    def to_tool_result(self) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        return [types.TextContent(type="text", text=self.to_text())]


@dataclass
class SentryReplayData:
    replay_id: str
    project_id: str
    timestamp: str
    duration: int
    environment: str
    urls: list[str]
    error_ids: list[str]
    # Browser info
    browser_name: str
    browser_version: str
    # Device info
    device_name: str
    device_family: str
    os_name: str
    os_version: str
    # User info
    user_name: str | None
    user_email: str | None
    # Activity counts
    activity_count: int
    dead_clicks: int
    rage_clicks: int
    error_count: int
    
    def to_text(self) -> str:
        basic_info = f"""
### Sentry Replay Details

| Field | Value |
|-------|-------|
| ID | {self.replay_id} |
| Project | {self.project_id} |
| Environment | {self.environment} |
| Duration | {self.duration}ms |
| Timestamp | {self.timestamp} |
| URLs Visited | {', '.join(self.urls)} |
| Error IDs | {', '.join(self.error_ids) if self.error_ids else 'None'} |

### Device Information

| Field | Value |
|-------|-------|
| Browser | {self.browser_name} {self.browser_version} |
| Device | {self.device_name} ({self.device_family}) |
| OS | {self.os_name} {self.os_version} |

### User Information

| Field | Value |
|-------|-------|
| Name | {self.user_name or 'Anonymous'} |
| Email | {self.user_email or 'N/A'} |

### Activity Metrics

| Metric | Count |
|--------|-------|
| Total Activity | {self.activity_count} |
| Dead Clicks | {self.dead_clicks} |
| Rage Clicks | {self.rage_clicks} |
| Errors | {self.error_count} |
"""
        return basic_info
    
    def to_tool_result(self) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        return [types.TextContent(type="text", text=self.to_text())]


@dataclass
class SentryReleaseData:
    version: str
    url: str
    projects: list[str]
    dateCreated: str
    
    def to_text(self) -> str:
        return f"""
Sentry Release Created:
Version: {self.version}
URL: {self.url}
Projects: {', '.join(self.projects)}
Date Created: {self.dateCreated}
        """
    
    def to_tool_result(self) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        return [types.TextContent(type="text", text=self.to_text())]


@dataclass
class SentryIssueData:
    title: str
    issue_id: str
    status: str
    level: str
    first_seen: str
    last_seen: str
    count: int
    stacktrace: str
    # New fields
    culprit: str
    platform: str | None
    project_name: str | None
    project_slug: str | None
    priority: str | None
    user_count: int
    tags: list[dict]
    stats: dict

    def to_text(self) -> str:
        # Format tags as a string
        tags_text = "\n".join([
            f"  {tag['key']}: {tag['name']} ({tag['totalValues']} values)"
            for tag in self.tags
        ]) if self.tags else "  No tags"

        return f"""
Sentry Issue: {self.title}
Issue ID: {self.issue_id}
Project: {self.project_name or 'Unknown'} ({self.project_slug or 'Unknown'})
Status: {self.status}
Level: {self.level}
Priority: {self.priority or 'Not set'}
Platform: {self.platform or 'Unknown'}
Culprit: {self.culprit}

First Seen: {self.first_seen}
Last Seen: {self.last_seen}
Event Count: {self.count}
Affected Users: {self.user_count}

Tags:
{tags_text}

Stacktrace:
{self.stacktrace}
        """

    def to_prompt_result(self) -> types.GetPromptResult:
        return types.GetPromptResult(
            description=f"Sentry Issue: {self.title}",
            messages=[
                types.PromptMessage(
                    role="user", content=types.TextContent(type="text", text=self.to_text())
                )
            ],
        )

    def to_tool_result(self) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        return [types.TextContent(type="text", text=self.to_text())]


class SentryError(Exception):
    pass


def extract_issue_id(issue_id_or_url: str) -> str:
    """
    Extracts the Sentry issue ID from either a full URL or a standalone ID.

    This function validates the input and returns the numeric issue ID.
    It raises SentryError for invalid inputs, including empty strings,
    non-Sentry URLs, malformed paths, and non-numeric IDs.
    """
    if not issue_id_or_url:
        raise SentryError("Missing issue_id_or_url argument")

    if issue_id_or_url.startswith(("http://", "https://")):
        parsed_url = urlparse(issue_id_or_url)
        if not parsed_url.hostname or not parsed_url.hostname.endswith(".sentry.io"):
            raise SentryError("Invalid Sentry URL. Must be a URL ending with .sentry.io")

        path_parts = parsed_url.path.strip("/").split("/")
        if len(path_parts) < 2 or path_parts[0] != "issues":
            raise SentryError(
                "Invalid Sentry issue URL. Path must contain '/issues/{issue_id}'"
            )

        issue_id = path_parts[-1]
    else:
        issue_id = issue_id_or_url

    if not issue_id.isdigit():
        raise SentryError("Invalid Sentry issue ID. Must be a numeric value.")

    return issue_id


def extract_replay_id(replay_id_or_url: str) -> tuple[str, str]:
    """
    Extracts the Sentry replay ID and org slug from either a full URL or standalone IDs.
    
    Args:
        replay_id_or_url: Either a full Sentry replay URL or "org_slug:replay_id" format
        
    Returns:
        Tuple of (org_slug, replay_id)
    """
    if not replay_id_or_url:
        raise SentryError("Missing replay_id_or_url argument")

    if replay_id_or_url.startswith(("http://", "https://")):
        parsed_url = urlparse(replay_id_or_url)
        if not parsed_url.hostname or not parsed_url.hostname.endswith(".sentry.io"):
            raise SentryError("Invalid Sentry URL. Must be a URL ending with .sentry.io")

        # Extract org slug from hostname (e.g., "buildwithcode.sentry.io")
        org_slug = parsed_url.hostname.split('.')[0]
        
        path_parts = parsed_url.path.strip("/").split("/")
        if len(path_parts) < 2 or path_parts[0] != "replays":
            raise SentryError(
                "Invalid Sentry replay URL. Path must contain '/replays/{replay_id}'"
            )
        replay_id = path_parts[1]

        # Extract project ID from query parameters
        query_params = dict(param.split('=') for param in parsed_url.query.split('&') if '=' in param)
        project_id = query_params.get('project')
        if not project_id:
            raise SentryError("Missing project ID in replay URL query parameters")

        replay_id = path_parts[-1]
    else:
        # Expect format: org_slug:replay_id
        try:
            org_slug, replay_id = replay_id_or_url.split(":")
        except ValueError:
            raise SentryError(
                "Invalid replay ID format. Must be either a URL or 'org_slug:replay_id'"
            )

    return org_slug, replay_id


def extract_trace_id(trace_id_or_url: str) -> tuple[str, str]:
    """
    Extracts the Sentry trace ID and project ID from either a full URL or standalone IDs.
    
    Args:
        trace_id_or_url: Either a full Sentry performance URL or "project_id:trace_id" format
        
    Returns:
        Tuple of (project_id, trace_id)
    """
    if not trace_id_or_url:
        raise SentryError("Missing trace_id_or_url argument")

    if trace_id_or_url.startswith(("http://", "https://")):
        parsed_url = urlparse(trace_id_or_url)
        if not parsed_url.hostname or not parsed_url.hostname.endswith(".sentry.io"):
            raise SentryError("Invalid Sentry URL. Must be a URL ending with .sentry.io")

        path_parts = parsed_url.path.strip("/").split("/")
        if len(path_parts) < 4 or path_parts[-2] != "performance":
            raise SentryError(
                "Invalid Sentry trace URL. Path must contain '/projects/{org}/{project}/performance/{trace_id}'"
            )

        project_id = path_parts[-3]
        trace_id = path_parts[-1]
    else:
        # Expect format: project_id:trace_id
        try:
            project_id, trace_id = trace_id_or_url.split(":")
        except ValueError:
            raise SentryError(
                "Invalid trace ID format. Must be either a URL or 'project_id:trace_id'"
            )

    return project_id, trace_id


def create_stacktrace(latest_event: dict) -> str:
    """
    Creates a formatted stacktrace string from the latest Sentry event.

    This function extracts exception information and stacktrace details from the
    provided event dictionary, formatting them into a human-readable string.
    It handles multiple exceptions and includes file, line number, and function
    information for each frame in the stacktrace.

    Args:
        latest_event (dict): A dictionary containing the latest Sentry event data.

    Returns:
        str: A formatted string containing the stacktrace information,
             or "No stacktrace found" if no relevant data is present.
    """
    stacktraces = []
    for entry in latest_event.get("entries", []):
        if entry["type"] != "exception":
            continue

        exception_data = entry["data"]["values"]
        for exception in exception_data:
            exception_type = exception.get("type", "Unknown")
            exception_value = exception.get("value", "")
            stacktrace = exception.get("stacktrace")

            stacktrace_text = f"Exception: {exception_type}: {exception_value}\n\n"
            if stacktrace:
                stacktrace_text += "Stacktrace:\n"
                for frame in stacktrace.get("frames", []):
                    filename = frame.get("filename", "Unknown")
                    lineno = frame.get("lineNo", "?")
                    function = frame.get("function", "Unknown")

                    stacktrace_text += f"{filename}:{lineno} in {function}\n"

                    if "context" in frame:
                        context = frame["context"]
                        for ctx_line in context:
                            stacktrace_text += f"    {ctx_line[1]}\n"

                    stacktrace_text += "\n"

            stacktraces.append(stacktrace_text)

    return "\n".join(stacktraces) if stacktraces else "No stacktrace found"


async def handle_get_trace(
    http_client: httpx.AsyncClient,
    auth_token: str,
    trace_id_or_url: str
) -> SentryTraceData:
    """
    Retrieves trace data from Sentry.
    
    Args:
        http_client: The HTTP client to use
        auth_token: Sentry authentication token
        trace_id_or_url: Either a full Sentry performance URL or "project_id:trace_id" format
        
    Returns:
        SentryTraceData object containing the trace information
    """
    try:
        project_id, trace_id = extract_trace_id(trace_id_or_url)
        
        # First get the organization slug by listing organizations
        orgs_response = await http_client.get(
            "organizations/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        if orgs_response.status_code == 401:
            raise McpError("Error: Unauthorized. Please check your MCP_SENTRY_AUTH_TOKEN token.")
            
        orgs_response.raise_for_status()
        orgs_data = orgs_response.json()
        
        if not orgs_data:
            raise McpError("No organizations found for this auth token")
            
        org_slug = orgs_data[0]["slug"]  # Use first available org
        
        # Get project details using org context
        project_response = await http_client.get(
            f"projects/{org_slug}/{project_id}/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        if project_response.status_code == 401:
            raise McpError("Error: Unauthorized. Please check your MCP_SENTRY_AUTH_TOKEN token.")
            
        project_response.raise_for_status()
        
        # Now fetch the trace data using the correct API endpoint
        response = await http_client.get(
            f"organizations/{org_slug}/projects/{project_id}/events/{trace_id}/",
            headers={"Authorization": f"Bearer {auth_token}"},
            params={
                "type": "transaction",
                "field": [
                    "transaction",
                    "timestamp",
                    "start_timestamp",
                    "spans",
                    "tags",
                    "contexts"
                ]
            }
        )
        
        if response.status_code == 401:
            raise McpError("Error: Unauthorized. Please check your MCP_SENTRY_AUTH_TOKEN token.")
        elif response.status_code == 404:
            raise McpError("Trace not found. It may have been deleted or you may not have permission to access it.")
            
        response.raise_for_status()
        trace_data = response.json()
        
        # Calculate duration from start_timestamp and timestamp if available
        duration = 0
        if "start_timestamp" in trace_data and "timestamp" in trace_data:
            try:
                start_time = float(trace_data["start_timestamp"])
                end_time = float(trace_data["timestamp"])
                duration = (end_time - start_time) * 1000  # Convert to milliseconds
            except (ValueError, TypeError):
                duration = trace_data.get("duration", 0)
        else:
            duration = trace_data.get("duration", 0)
        
        return SentryTraceData(
            trace_id=trace_id,
            transaction=trace_data.get("transaction", ""),
            project_id=project_id,
            timestamp=trace_data.get("dateCreated", ""),
            duration=duration,
            status=trace_data.get("status", "unknown"),
            spans=trace_data.get("spans", []),
            tags=trace_data.get("tags", {})
        )
        
    except SentryError as e:
        raise McpError(str(e))
    except httpx.HTTPStatusError as e:
        raise McpError(f"Error fetching Sentry trace: {str(e)}")
    except Exception as e:
        raise McpError(f"An error occurred: {str(e)}")


async def handle_get_replay(
    http_client: httpx.AsyncClient,
    auth_token: str,
    replay_id_or_url: str
) -> SentryReplayData:
    """
    Retrieves replay data from Sentry.
    
    Args:
        http_client: The HTTP client to use
        auth_token: Sentry authentication token
        replay_id_or_url: Either a full Sentry replay URL or "org_slug:replay_id" format
        
    Returns:
        SentryReplayData object containing the replay information
    """
    try:
        org_slug, replay_id = extract_replay_id(replay_id_or_url)
        
        # First get the organization slug by listing organizations
        orgs_response = await http_client.get(
            "organizations/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        if orgs_response.status_code == 401:
            raise McpError("Error: Unauthorized. Please check your MCP_SENTRY_AUTH_TOKEN token.")
            
        orgs_response.raise_for_status()
        orgs_data = orgs_response.json()
        
        if not orgs_data:
            raise McpError("No organizations found for this auth token")
            
        org_slug = orgs_data[0]["slug"]  # Use first available org
        
        # Use the correct API endpoint format for replays
        response = await http_client.get(
            f"organizations/{org_slug}/replays/{replay_id}/",
            headers={"Authorization": f"Bearer {auth_token}"},
            params={
                "detailed": "1"  # Get detailed replay information
            }
        )
        
        if response.status_code == 401:
            raise McpError("Error: Unauthorized. Please check your MCP_SENTRY_AUTH_TOKEN token.")
        elif response.status_code == 404:
            raise McpError("Replay not found. It may have been deleted or you may not have permission to access it.")
            
        response.raise_for_status()
        response_json = response.json()
        
        # Extract the nested data
        if "data" not in response_json:
            raise McpError("Unexpected API response format: missing 'data' key")
            
        replay_data = response_json["data"]
        
        return SentryReplayData(
            replay_id=replay_id,
            project_id=replay_data.get("project_id", ""),
            timestamp=replay_data.get("started_at", ""),
            duration=replay_data.get("duration", 0),
            environment=replay_data.get("environment", "unknown"),
            urls=replay_data.get("urls", []),
            error_ids=replay_data.get("error_ids", []),
            # Browser info
            browser_name=replay_data.get("browser", {}).get("name", "Unknown"),
            browser_version=replay_data.get("browser", {}).get("version", "Unknown"),
            # Device info
            device_name=replay_data.get("device", {}).get("name", "Unknown"),
            device_family=replay_data.get("device", {}).get("family", "Unknown"),
            os_name=replay_data.get("os", {}).get("name", "Unknown"),
            os_version=replay_data.get("os", {}).get("version", "Unknown"),
            # User info
            user_name=replay_data.get("user", {}).get("display_name"),
            user_email=replay_data.get("user", {}).get("email"),
            # Activity counts
            activity_count=replay_data.get("activity", 0),
            dead_clicks=replay_data.get("count_dead_clicks", 0),
            rage_clicks=replay_data.get("count_rage_clicks", 0),
            error_count=replay_data.get("count_errors", 0)
        )
        
    except SentryError as e:
        raise McpError(str(e))
    except httpx.HTTPStatusError as e:
        raise McpError(f"Error fetching Sentry replay: {str(e)}")
    except Exception as e:
        raise McpError(f"An error occurred: {str(e)}")


async def handle_create_release(
    http_client: httpx.AsyncClient,
    auth_token: str,
    version: str,
    projects: list[str],
    refs: list[dict] | None = None,
) -> SentryReleaseData:
    """
    Creates a new release in Sentry.
    
    Args:
        http_client: The HTTP client to use
        auth_token: Sentry authentication token
        version: The version identifier for the release
        projects: List of project slugs to associate the release with
        refs: Optional list of repository references
        
    Returns:
        SentryReleaseData object containing the created release information
    """
    try:
        # First get the organization slug by listing organizations
        orgs_response = await http_client.get(
            "organizations/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        if orgs_response.status_code == 401:
            raise McpError("Error: Unauthorized. Please check your MCP_SENTRY_AUTH_TOKEN token.")
            
        orgs_response.raise_for_status()
        orgs_data = orgs_response.json()
        
        if not orgs_data:
            raise McpError("No organizations found for this auth token")
            
        org_slug = orgs_data[0]["slug"]  # Use first available org
        
        payload = {
            "version": version,
            "projects": projects,
        }
        
        if refs:
            payload["refs"] = refs
            
        response = await http_client.post(
            f"organizations/{org_slug}/releases/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=payload
        )
        
        if response.status_code == 401:
            raise McpError("Error: Unauthorized. Please check your MCP_SENTRY_AUTH_TOKEN token.")
            
        response.raise_for_status()
        release_data = response.json()
        
        return SentryReleaseData(
            version=release_data["version"],
            url=release_data.get("url", ""),
            projects=release_data["projects"],
            dateCreated=release_data["dateCreated"]
        )
        
    except httpx.HTTPStatusError as e:
        raise McpError(f"Error creating Sentry release: {str(e)}")
    except Exception as e:
        raise McpError(f"An error occurred: {str(e)}")


async def handle_sentry_issue(
    http_client: httpx.AsyncClient, auth_token: str, issue_id_or_url: str
) -> SentryIssueData:
    try:
        issue_id = extract_issue_id(issue_id_or_url)

        # First get the organization slug by listing organizations
        orgs_response = await http_client.get(
            "organizations/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        if orgs_response.status_code == 401:
            raise McpError("Error: Unauthorized. Please check your MCP_SENTRY_AUTH_TOKEN token.")
            
        orgs_response.raise_for_status()
        orgs_data = orgs_response.json()
        
        if not orgs_data:
            raise McpError("No organizations found for this auth token")
            
        org_slug = orgs_data[0]["slug"]  # Use first available org

        # Get issue details using org context
        response = await http_client.get(
            f"organizations/{org_slug}/issues/{issue_id}/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        if response.status_code == 401:
            raise McpError("Error: Unauthorized. Please check your MCP_SENTRY_AUTH_TOKEN token.")
        elif response.status_code == 404:
            raise McpError("Issue not found. It may have been deleted or you may not have permission to access it.")
            
        response.raise_for_status()
        issue_data = response.json()

        # Get issue hashes for stacktrace
        hashes_response = await http_client.get(
            f"issues/{issue_id}/hashes/",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        hashes_response.raise_for_status()
        hashes = hashes_response.json()

        stacktrace = "No stacktrace available"
        if hashes:
            latest_event = hashes[0]["latestEvent"]
            stacktrace = create_stacktrace(latest_event)

        return SentryIssueData(
            title=issue_data["title"],
            issue_id=issue_id,
            status=issue_data["status"],
            level=issue_data["level"],
            first_seen=issue_data["firstSeen"],
            last_seen=issue_data["lastSeen"],
            count=int(issue_data["count"]),
            stacktrace=stacktrace,
            # New fields
            culprit=issue_data.get("culprit", "Unknown"),
            platform=issue_data.get("platform"),
            project_name=issue_data.get("project", {}).get("name"),
            project_slug=issue_data.get("project", {}).get("slug"),
            priority=issue_data.get("priority"),
            user_count=issue_data.get("userCount", 0),
            tags=issue_data.get("tags", []),
            stats=issue_data.get("stats", {})
        )

    except SentryError as e:
        raise McpError(str(e))
    except httpx.HTTPStatusError as e:
        raise McpError(f"Error fetching Sentry issue: {str(e)}")
    except Exception as e:
        raise McpError(f"An error occurred: {str(e)}")


async def serve(auth_token: str) -> Server:
    server = Server("sentry")
    http_client = httpx.AsyncClient(base_url=SENTRY_API_BASE)

    @server.list_prompts()
    async def handle_list_prompts() -> list[types.Prompt]:
        return [
            types.Prompt(
                name="sentry-issue",
                description="Retrieve a Sentry issue by ID or URL",
                arguments=[
                    types.PromptArgument(
                        name="issue_id_or_url",
                        description="Sentry issue ID or URL",
                        required=True,
                    )
                ],
            )
        ]

    @server.get_prompt()
    async def handle_get_prompt(
        name: str, arguments: dict[str, str] | None
    ) -> types.GetPromptResult:
        if name != "sentry-issue":
            raise ValueError(f"Unknown prompt: {name}")

        issue_id_or_url = (arguments or {}).get("issue_id_or_url", "")
        issue_data = await handle_sentry_issue(http_client, auth_token, issue_id_or_url)
        return issue_data.to_prompt_result()

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="get_sentry_issue",
                description="""Retrieve and analyze a Sentry issue by ID or URL. Use this tool when you need to:
                - Investigate production errors and crashes
                - Access detailed stacktraces from Sentry
                - Analyze error patterns and frequencies
                - Get information about when issues first/last occurred
                - Review error counts and status""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "issue_id_or_url": {
                            "type": "string",
                            "description": "Sentry issue ID or URL to analyze"
                        }
                    },
                    "required": ["issue_id_or_url"]
                }
            ),
            types.Tool(
                name="create_release",
                description="""Create a new release in Sentry. Use this tool when you need to:
                - Create a new release for deployment tracking
                - Associate commits with a release
                - Track release adoption and stability
                - Monitor release health metrics""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "version": {
                            "type": "string",
                            "description": "Unique identifier for the release (e.g. commit hash, version number)"
                        },
                        "projects": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                            "description": "List of project slugs to associate the release with"
                        },
                        "refs": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "repository": {
                                        "type": "string"
                                    },
                                    "commit": {
                                        "type": "string"
                                    },
                                    "previousCommit": {
                                        "type": "string"
                                    }
                                }
                            },
                            "description": "Optional list of repository references"
                        }
                    },
                    "required": ["version", "projects"]
                }
            ),
            types.Tool(
                name="get_replay",
                description="""Retrieve and analyze a Sentry session replay. Use this tool when you need to:
                - Access session replay metadata
                - Link replays to related errors
                - Analyze user activity during a session
                - Get replay duration and timing information""",
                inputSchema={
                    "type": "object",
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": {
                                "url": {
                                    "type": "string",
                                    "description": "Full Sentry replay URL (e.g., https://buildwithcode.sentry.io/replays/{replay_id})"
                                }
                            },
                            "required": ["url"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "organization_slug": {
                                    "type": "string",
                                    "description": "Sentry organization slug (e.g., 'buildwithcode')"
                                },
                                "replay_id": {
                                    "type": "string",
                                    "description": "Sentry replay ID"
                                }
                            },
                            "required": ["organization_slug", "replay_id"]
                        }
                    ]
                }
            ),
            types.Tool(
                name="get_trace",
                description="""Retrieve and analyze a Sentry performance trace. Use this tool when you need to:
                - Investigate transaction performance
                - Analyze distributed tracing data
                - View span operations and timings
                - Check transaction status and tags
                - Monitor end-to-end request flow""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "trace_id_or_url": {
                            "type": "string",
                            "description": "Sentry trace ID (project_id:trace_id format) or performance URL"
                        }
                    },
                    "required": ["trace_id_or_url"]
                }
            )
        ]

    @server.call_tool()
    async def handle_call_tool(
        name: str, arguments: dict | None
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        if not arguments:
            raise ValueError("Missing arguments")
            
        if name == "get_sentry_issue":
            if "issue_id_or_url" not in arguments:
                raise ValueError("Missing issue_id_or_url argument")
            issue_data = await handle_sentry_issue(http_client, auth_token, arguments["issue_id_or_url"])
            return issue_data.to_tool_result()
            
        elif name == "create_release":
            if "version" not in arguments or "projects" not in arguments:
                raise ValueError("Missing required arguments: version and projects")
            release_data = await handle_create_release(
                http_client,
                auth_token,
                arguments["version"],
                arguments["projects"],
                arguments.get("refs")
            )
            return release_data.to_tool_result()
            
        elif name == "get_replay":
            if "url" in arguments:
                replay_data = await handle_get_replay(http_client, auth_token, arguments["url"])
            elif "organization_slug" in arguments and "replay_id" in arguments:
                # Construct the input format expected by handle_get_replay
                replay_input = f"{arguments['organization_slug']}:{arguments['replay_id']}"
                replay_data = await handle_get_replay(http_client, auth_token, replay_input)
            else:
                raise ValueError("Must provide either url or both organization_slug and replay_id")
            return replay_data.to_tool_result()
            
        elif name == "get_trace":
            if "trace_id_or_url" not in arguments:
                raise ValueError("Missing trace_id_or_url argument")
            trace_data = await handle_get_trace(
                http_client,
                auth_token,
                arguments["trace_id_or_url"]
            )
            return trace_data.to_tool_result()
            
        raise ValueError(f"Unknown tool: {name}")

    return server

@click.command()
@click.option(
    "--auth-token",
    envvar="SENTRY_TOKEN",
    required=True,
    help="Sentry authentication token",
)
def main(auth_token: str):
    async def _run():
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            server = await serve(auth_token)
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="sentry",
                    server_version="0.4.1",
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )

    asyncio.run(_run())
