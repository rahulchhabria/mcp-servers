import asyncio
from dataclasses import dataclass
from urllib.parse import urlparse
import logging
import json

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

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create console handler with formatting
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

def log_response(response: httpx.Response, context: str = ""):
    """Helper function to log API response details"""
    try:
        logger.debug(f"{context} API Request URL: {response.request.url}")
        logger.debug(f"{context} API Request Headers: {response.request.headers}")
        logger.debug(f"{context} API Response Status: {response.status_code}")
        logger.debug(f"{context} API Response Headers: {response.headers}")
        
        # Try to parse and log response content
        try:
            content = response.json()
            logger.debug(f"{context} API Response Content: {json.dumps(content, indent=2)}")
        except json.JSONDecodeError:
            logger.debug(f"{context} API Response Content (raw): {response.text}")
    except Exception as e:
        logger.error(f"Error logging response: {str(e)}")


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

    def to_text(self) -> str:
        return f"""
Sentry Issue: {self.title}
Issue ID: {self.issue_id}
Status: {self.status}
Level: {self.level}
First Seen: {self.first_seen}
Last Seen: {self.last_seen}
Event Count: {self.count}

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


@dataclass
class SentryEventData:
    event_id: str
    issue_id: str
    project_id: str
    timestamp: str
    title: str
    message: str
    level: str
    platform: str
    stacktrace: str | None
    tags: list[dict]
    contexts: dict
    
    def to_text(self) -> str:
        tags_text = "\n".join([
            f"  {tag['key']}: {tag['value']}"
            for tag in self.tags
        ])
        
        return f"""
Sentry Event Details:
Event ID: {self.event_id}
Issue ID: {self.issue_id}
Project: {self.project_id}
Title: {self.title}
Message: {self.message}
Level: {self.level}
Platform: {self.platform}
Timestamp: {self.timestamp}

Tags:
{tags_text}

Stacktrace:
{self.stacktrace if self.stacktrace else 'No stacktrace available'}
        """
    
    def to_tool_result(self) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        return [types.TextContent(type="text", text=self.to_text())]


class SentryError(Exception):
    pass


def parse_sentry_url(url: str, expected_path_type: str) -> tuple[str, str]:
    """
    Parses a Sentry URL to extract organization slug and ID.
    
    Args:
        url: Full Sentry URL (e.g., https://rc-sentry-projects.sentry.io/replays/278eb868cf4f4527a7e6e39b0d116a66/)
        expected_path_type: The expected path component ('issues', 'replays', or 'traces')
        
    Returns:
        Tuple of (org_slug, id)
        
    Raises:
        SentryError: If URL format is invalid
    """
    try:
        parsed_url = urlparse(url)
        if not parsed_url.hostname or not parsed_url.hostname.endswith(".sentry.io"):
            raise SentryError("Invalid Sentry URL. Must be a URL ending with .sentry.io")

        # Extract org slug from hostname, preserving any hyphens
        # For hostname like "rc-sentry-projects.sentry.io", get "rc-sentry-projects"
        hostname_parts = parsed_url.hostname.split('.')
        if len(hostname_parts) < 2:
            raise SentryError("Invalid Sentry URL format: hostname must contain at least two parts")
            
        org_slug = hostname_parts[0]
        logger.debug(f"Extracted organization slug: {org_slug} from hostname: {parsed_url.hostname}")
        
        # Split path and remove empty strings and query parameters
        path_parts = [p for p in parsed_url.path.split("/") if p]
        logger.debug(f"Path parts after splitting: {path_parts}")
        
        # Handle special case for traces which have an extra 'trace' component
        if expected_path_type == 'traces':
            if len(path_parts) < 3 or path_parts[0] != 'traces' or path_parts[1] != 'trace':
                raise SentryError(f"Invalid Sentry {expected_path_type} URL. Path must contain '/traces/trace/{{id}}'")
            item_id = path_parts[2]
            logger.debug(f"Extracted trace ID: {item_id} from path parts: {path_parts}")
        else:
            if len(path_parts) < 2 or path_parts[0] != expected_path_type:
                raise SentryError(f"Invalid Sentry {expected_path_type} URL. Path must contain '/{expected_path_type}/{{id}}'")
            # Take the ID part and remove any trailing characters after potential query params
            item_id = path_parts[1].split('?')[0]
            logger.debug(f"Extracted {expected_path_type} ID: {item_id} from path parts: {path_parts}")
        
        # Additional validation for the extracted values
        if not org_slug or not item_id:
            raise SentryError(f"Failed to extract valid organization slug ({org_slug}) or item ID ({item_id})")
            
        logger.debug(f"Final extracted values - org_slug: {org_slug}, item_id: {item_id}")
        return org_slug, item_id
        
    except Exception as e:
        logger.error(f"Error parsing Sentry URL '{url}': {str(e)}")
        raise


def extract_issue_id(issue_id_or_url: str) -> str:
    """
    Extracts the Sentry issue ID from either a full URL or a standalone ID.
    """
    if not issue_id_or_url:
        raise SentryError("Missing issue_id_or_url argument")

    if issue_id_or_url.startswith(("http://", "https://")):
        _, issue_id = parse_sentry_url(issue_id_or_url, "issues")
    else:
        issue_id = issue_id_or_url

    if not issue_id.isdigit():
        raise SentryError("Invalid Sentry issue ID. Must be a numeric value.")

    return issue_id


def extract_replay_id(replay_id_or_url: str) -> tuple[str, str]:
    """
    Extracts the Sentry replay ID and org slug from either a full URL or standalone IDs.
    """
    if not replay_id_or_url:
        raise SentryError("Missing replay_id_or_url argument")

    if replay_id_or_url.startswith(("http://", "https://")):
        return parse_sentry_url(replay_id_or_url, "replays")
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
    Extracts the Sentry trace ID and organization slug from either a full URL or standalone IDs.
    
    Args:
        trace_id_or_url: Either a full Sentry trace URL or "org_slug:trace_id" format
        
    Returns:
        Tuple of (org_slug, trace_id)
        
    Raises:
        SentryError: If format is invalid
    """
    if not trace_id_or_url:
        raise SentryError("Missing trace_id_or_url argument")

    if trace_id_or_url.startswith(("http://", "https://")):
        return parse_sentry_url(trace_id_or_url, "traces")
    else:
        # Expect format: org_slug:trace_id
        try:
            org_slug, trace_id = trace_id_or_url.split(":")
        except ValueError:
            raise SentryError(
                "Invalid trace ID format. Must be either a URL or 'org_slug:trace_id'"
            )
        return org_slug, trace_id


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
        trace_id_or_url: Either a full Sentry trace URL or "org_slug:trace_id" format
        
    Returns:
        SentryTraceData object containing the trace information
    """
    try:
        # Get org_slug and trace_id, preserving any hyphens in org_slug
        org_slug, trace_id = extract_trace_id(trace_id_or_url)
        logger.debug(f"[Trace] Using organization slug: {org_slug} for trace ID: {trace_id}")
        
        # Construct API URL
        api_url = f"organizations/{org_slug}/events/{trace_id}/"
        logger.debug(f"[Trace] Making request to: {SENTRY_API_BASE}{api_url}")
        
        # Fetch the trace data using the organization endpoint
        response = await http_client.get(
            api_url,
            headers={
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json",
            },
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
        
        # Log full response details
        log_response(response, "[Trace]")
        
        if response.status_code == 401:
            logger.error("[Trace] Authentication failed with 401 status code")
            raise McpError("Error: Unauthorized. Please check your MCP_SENTRY_AUTH_TOKEN token.")
        elif response.status_code == 404:
            logger.error("[Trace] Resource not found with 404 status code")
            raise McpError("Trace not found. It may have been deleted or you may not have permission to access it.")
            
        response.raise_for_status()
        trace_data = response.json()
        
        if not trace_data:
            logger.error("[Trace] Received empty response from Sentry API")
            raise McpError("Received empty response from Sentry API")
            
        logger.debug(f"[Trace] Successfully parsed trace data with keys: {list(trace_data.keys())}")
        
        # Calculate duration from start_timestamp and timestamp if available
        duration = 0
        if "start_timestamp" in trace_data and "timestamp" in trace_data:
            try:
                start_time = float(trace_data["start_timestamp"])
                end_time = float(trace_data["timestamp"])
                duration = (end_time - start_time) * 1000  # Convert to milliseconds
                logger.debug(f"[Trace] Calculated duration: {duration}ms from timestamps")
            except (ValueError, TypeError) as e:
                logger.warning(f"[Trace] Failed to calculate duration from timestamps: {str(e)}")
                duration = trace_data.get("duration", 0)
        else:
            logger.debug("[Trace] Using duration directly from trace data")
            duration = trace_data.get("duration", 0)
        
        # Create SentryTraceData object
        trace_obj = SentryTraceData(
            trace_id=trace_id,
            transaction=trace_data.get("transaction", ""),
            project_id=trace_data.get("project_id", ""),
            timestamp=trace_data.get("dateCreated", ""),
            duration=duration,
            status=trace_data.get("status", "unknown"),
            spans=trace_data.get("spans", []),
            tags=trace_data.get("tags", {})
        )
        
        logger.debug("[Trace] Successfully created SentryTraceData object")
        return trace_obj
        
    except SentryError as e:
        logger.error(f"[Trace] SentryError occurred: {str(e)}")
        raise McpError(str(e))
    except httpx.HTTPStatusError as e:
        logger.error(f"[Trace] HTTP error occurred: {str(e)}")
        raise McpError(f"Error fetching Sentry trace: {str(e)}")
    except Exception as e:
        logger.error(f"[Trace] Unexpected error occurred: {str(e)}")
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
        # Get org_slug and replay_id, preserving any hyphens in org_slug
        org_slug, replay_id = extract_replay_id(replay_id_or_url)
        logger.debug(f"[Replay] Using organization slug: {org_slug} for replay ID: {replay_id}")
        
        # Construct API URL
        api_url = f"organizations/{org_slug}/replays/{replay_id}/"
        logger.debug(f"[Replay] Making request to: {SENTRY_API_BASE}{api_url}")
        
        # Use the correct API endpoint format for replays
        response = await http_client.get(
            api_url,
            headers={
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json",
            },
            params={"detailed": "1"}
        )
        
        # Log full response details
        log_response(response, "[Replay]")
        
        if response.status_code == 401:
            logger.error("[Replay] Authentication failed with 401 status code")
            raise McpError("Error: Unauthorized. Please check your MCP_SENTRY_AUTH_TOKEN token.")
        elif response.status_code == 404:
            logger.error("[Replay] Resource not found with 404 status code")
            raise McpError("Replay not found. It may have been deleted or you may not have permission to access it.")
            
        response.raise_for_status()
        response_data = response.json()
        
        if not response_data:
            logger.error("[Replay] Received empty response from Sentry API")
            raise McpError("Received empty response from Sentry API")
            
        # Extract the nested data
        if "data" not in response_data:
            logger.error("[Replay] Response missing 'data' key")
            raise McpError("Unexpected API response format: missing 'data' key")
            
        replay_data = response_data["data"]
        logger.debug(f"[Replay] Successfully parsed replay data with keys: {list(replay_data.keys())}")
        
        # Create SentryReplayData object
        replay_obj = SentryReplayData(
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
        
        logger.debug("[Replay] Successfully created SentryReplayData object")
        return replay_obj
        
    except SentryError as e:
        logger.error(f"[Replay] SentryError occurred: {str(e)}")
        raise McpError(str(e))
    except httpx.HTTPStatusError as e:
        logger.error(f"[Replay] HTTP error occurred: {str(e)}")
        raise McpError(f"Error fetching Sentry replay: {str(e)}")
    except Exception as e:
        logger.error(f"[Replay] Unexpected error occurred: {str(e)}")
        raise McpError(f"An error occurred: {str(e)}")


async def handle_create_release(
    http_client: httpx.AsyncClient,
    auth_token: str,
    version: str,
    projects: list[str],
    org_slug: str,
    refs: list[dict] | None = None,
) -> SentryReleaseData:
    """
    Creates a new release in Sentry.
    
    Args:
        http_client: The HTTP client to use
        auth_token: Sentry authentication token
        version: The version identifier for the release
        projects: List of project slugs to associate the release with
        org_slug: The organization slug where the release should be created
        refs: Optional list of repository references
        
    Returns:
        SentryReleaseData object containing the created release information
    """
    try:
        logger.debug(f"Creating release version {version} for organization {org_slug}")
        
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

        response = await http_client.get(
            f"issues/{issue_id}/", headers={"Authorization": f"Bearer {auth_token}"}
        )
        if response.status_code == 401:
            raise McpError(
                "Error: Unauthorized. Please check your MCP_SENTRY_AUTH_TOKEN token."
            )
        response.raise_for_status()
        issue_data = response.json()

        # Get issue hashes
        hashes_response = await http_client.get(
            f"issues/{issue_id}/hashes/",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        hashes_response.raise_for_status()
        hashes = hashes_response.json()

        if not hashes:
            raise McpError("No Sentry events found for this issue")

        latest_event = hashes[0]["latestEvent"]
        stacktrace = create_stacktrace(latest_event)

        return SentryIssueData(
            title=issue_data["title"],
            issue_id=issue_id,
            status=issue_data["status"],
            level=issue_data["level"],
            first_seen=issue_data["firstSeen"],
            last_seen=issue_data["lastSeen"],
            count=issue_data["count"],
            stacktrace=stacktrace
        )

    except SentryError as e:
        raise McpError(str(e))
    except httpx.HTTPStatusError as e:
        raise McpError(f"Error fetching Sentry issue: {str(e)}")
    except Exception as e:
        raise McpError(f"An error occurred: {str(e)}")


async def handle_get_event(
    http_client: httpx.AsyncClient,
    auth_token: str,
    issue_id_or_url: str,
    event_id: str
) -> SentryEventData:
    """
    Retrieves a specific event from a Sentry issue.
    
    Args:
        http_client: The HTTP client to use
        auth_token: Sentry authentication token
        issue_id_or_url: Either a full Sentry issue URL or "org_slug:issue_id" format
        event_id: The specific event ID to retrieve
        
    Returns:
        SentryEventData object containing the event information
    """
    try:
        # Extract the org_slug and issue_id, preserving any hyphens in org_slug
        if issue_id_or_url.startswith(("http://", "https://")):
            org_slug, issue_id = parse_sentry_url(issue_id_or_url, "issues")
            logger.debug(f"[Event] Extracted from URL - org_slug: {org_slug}, issue_id: {issue_id}")
        else:
            # Expect format: org_slug:issue_id
            try:
                org_slug, issue_id = issue_id_or_url.split(":")
                logger.debug(f"[Event] Parsed from string - org_slug: {org_slug}, issue_id: {issue_id}")
            except ValueError:
                logger.error(f"[Event] Failed to parse issue_id_or_url: {issue_id_or_url}")
                raise SentryError(
                    "Invalid issue ID format. Must be either a URL or 'org_slug:issue_id'"
                )
                
        logger.debug(f"[Event] Using organization slug: {org_slug} for issue ID: {issue_id} and event ID: {event_id}")
        
        # Construct API URL
        api_url = f"organizations/{org_slug}/issues/{issue_id}/events/{event_id}/"
        logger.debug(f"[Event] Making request to: {SENTRY_API_BASE}{api_url}")
        
        # Get the event data
        response = await http_client.get(
            api_url,
            headers={
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json",
            }
        )
        
        # Log full response details
        log_response(response, "[Event]")
        
        if response.status_code == 401:
            logger.error("[Event] Authentication failed with 401 status code")
            raise McpError("Error: Unauthorized. Please check your MCP_SENTRY_AUTH_TOKEN token.")
        elif response.status_code == 404:
            logger.error("[Event] Resource not found with 404 status code")
            raise McpError("Event not found. It may have been deleted or you may not have permission to access it.")
            
        response.raise_for_status()
        event_data = response.json()
        
        if not event_data:
            logger.error("[Event] Received empty response from Sentry API")
            raise McpError("Received empty response from Sentry API")
            
        logger.debug(f"[Event] Successfully parsed event data with keys: {list(event_data.keys())}")
        
        # Extract stacktrace if available
        stacktrace = None
        for entry in event_data.get("entries", []):
            if entry["type"] == "exception":
                logger.debug("[Event] Found exception entry, extracting stacktrace")
                stacktrace = create_stacktrace({"entries": [entry]})
                break
        
        if not stacktrace:
            logger.debug("[Event] No stacktrace found in event data")
        
        # Create SentryEventData object
        event_obj = SentryEventData(
            event_id=event_data["eventID"],
            issue_id=event_data["groupID"],
            project_id=event_data.get("projectID", ""),
            timestamp=event_data["dateCreated"],
            title=event_data.get("title", ""),
            message=event_data.get("message", ""),
            level=event_data.get("level", "error"),
            platform=event_data.get("platform", "unknown"),
            stacktrace=stacktrace,
            tags=event_data.get("tags", []),
            contexts=event_data.get("contexts", {})
        )
        
        logger.debug("[Event] Successfully created SentryEventData object")
        return event_obj
        
    except SentryError as e:
        logger.error(f"[Event] SentryError occurred: {str(e)}")
        raise McpError(str(e))
    except httpx.HTTPStatusError as e:
        logger.error(f"[Event] HTTP error occurred: {str(e)}")
        raise McpError(f"Error fetching Sentry event: {str(e)}")
    except Exception as e:
        logger.error(f"[Event] Unexpected error occurred: {str(e)}")
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
                description="""Retrieve and analyze a Sentry issue. Accepts either:
                1. A full Sentry issue URL (e.g., https://org-name.sentry.io/issues/123456)
                2. Just the issue ID (e.g., 123456)""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "issue_id_or_url": {
                            "type": "string",
                            "description": "Either a full Sentry issue URL or just the numeric issue ID"
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
                                    "repository": {"type": "string"},
                                    "commit": {"type": "string"},
                                    "previousCommit": {"type": "string"}
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
                description="""Retrieve and analyze a Sentry session replay. Accepts either:
                1. A full Sentry replay URL (e.g., https://org-name.sentry.io/replays/abc123)
                2. Organization slug and replay ID in format: 'org-slug:replay-id'""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "replay_id_or_url": {
                            "type": "string",
                            "description": "Either a full Sentry replay URL or 'org-slug:replay-id' format"
                        }
                    },
                    "required": ["replay_id_or_url"]
                }
            ),
            types.Tool(
                name="get_trace",
                description="""Retrieve and analyze a Sentry performance trace. Accepts either:
                1. A full Sentry trace URL (e.g., https://org-name.sentry.io/traces/trace/abc123)
                2. Project ID and trace ID in format: 'project-id:trace-id'""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "trace_id_or_url": {
                            "type": "string",
                            "description": "Either a full Sentry trace URL or 'project-id:trace-id' format"
                        }
                    },
                    "required": ["trace_id_or_url"]
                }
            ),
            types.Tool(
                name="get_sentry_event",
                description="""Retrieve and analyze a specific Sentry event from an issue. Requires:
                1. Issue ID or URL (e.g., https://org-name.sentry.io/issues/123456 or just 123456)
                2. Event ID (e.g., ab29e1067f214acb8ce89f3a03be25e8)""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "issue_id_or_url": {
                            "type": "string",
                            "description": "Either a full Sentry issue URL or just the numeric issue ID"
                        },
                        "event_id": {
                            "type": "string",
                            "description": "The specific event ID to retrieve"
                        }
                    },
                    "required": ["issue_id_or_url", "event_id"]
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
            if "replay_id_or_url" in arguments:
                replay_data = await handle_get_replay(http_client, auth_token, arguments["replay_id_or_url"])
            else:
                raise ValueError("Missing replay_id_or_url argument")
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
            
        elif name == "get_sentry_event":
            if "issue_id_or_url" not in arguments or "event_id" not in arguments:
                raise ValueError("Missing required arguments: issue_id_or_url and event_id")
            event_data = await handle_get_event(
                http_client,
                auth_token,
                arguments["issue_id_or_url"],
                arguments["event_id"]
            )
            return event_data.to_tool_result()
            
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
