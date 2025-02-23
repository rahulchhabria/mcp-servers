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
class SentryTransactionData:
    transaction_id: str
    transaction_name: str
    project: str
    environment: str
    status: str
    duration: float  # in milliseconds
    timestamp: str
    spans: list[dict]

    def to_text(self) -> str:
        spans_text = "\n".join(
            f"- {span.get('op', 'unknown')}: {span.get('description', 'N/A')} "
            f"({span.get('duration', 0):.2f}ms)"
            for span in self.spans
        )
        
        return f"""
Sentry Transaction: {self.transaction_name}
Transaction ID: {self.transaction_id}
Project: {self.project}
Environment: {self.environment}
Status: {self.status}
Duration: {self.duration:.2f}ms
Timestamp: {self.timestamp}

Spans:
{spans_text}
        """

    def to_prompt_result(self) -> types.GetPromptResult:
        return types.GetPromptResult(
            description=f"Sentry Transaction: {self.transaction_name}",
            messages=[
                types.PromptMessage(
                    role="user", content=types.TextContent(type="text", text=self.to_text())
                )
            ],
        )

    def to_tool_result(self) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        return [types.TextContent(type="text", text=self.to_text())]


@dataclass
class SentryReleaseData:
    version: str
    project: str
    dateCreated: str
    dateReleased: str
    newGroups: int
    commits: list[dict]
    lastDeploy: dict | None
    stats: dict

    def to_text(self) -> str:
        commits_text = "\n".join(
            f"- {commit.get('message', 'No message')} "
            f"(by {commit.get('author', {}).get('name', 'Unknown')})"
            for commit in self.commits
        )

        deploy_text = ""
        if self.lastDeploy:
            deploy_text = f"""
Last Deployment:
- Environment: {self.lastDeploy.get('environment', 'Unknown')}
- Date: {self.lastDeploy.get('dateFinished', 'Unknown')}
- Status: {self.lastDeploy.get('status', 'Unknown')}"""

        return f"""
Sentry Release: {self.version}
Project: {self.project}
Created: {self.dateCreated}
Released: {self.dateReleased}
New Issues: {self.newGroups}

Commits:
{commits_text}
{deploy_text}
        """

    def to_prompt_result(self) -> types.GetPromptResult:
        return types.GetPromptResult(
            description=f"Sentry Release: {self.version}",
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


async def handle_sentry_transaction(
    http_client: httpx.AsyncClient, 
    auth_token: str, 
    transaction_id: str
) -> SentryTransactionData:
    try:
        response = await http_client.get(
            f"events/{transaction_id}/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        if response.status_code == 401:
            raise McpError(
                "Error: Unauthorized. Please check your MCP_SENTRY_AUTH_TOKEN token."
            )
        response.raise_for_status()
        transaction_data = response.json()

        return SentryTransactionData(
            transaction_id=transaction_id,
            transaction_name=transaction_data.get("transaction", "Unknown"),
            project=transaction_data.get("project", "Unknown"),
            environment=transaction_data.get("environment", "Unknown"),
            status=transaction_data.get("contexts", {}).get("trace", {}).get("status", "Unknown"),
            duration=transaction_data.get("duration", 0),
            timestamp=transaction_data.get("dateCreated", "Unknown"),
            spans=transaction_data.get("spans", [])
        )

    except httpx.HTTPStatusError as e:
        raise McpError(f"Error fetching Sentry transaction: {str(e)}")
    except Exception as e:
        raise McpError(f"An error occurred: {str(e)}")


async def handle_sentry_release(
    http_client: httpx.AsyncClient,
    auth_token: str,
    organization: str,
    project: str,
    version: str,
) -> SentryReleaseData:
    try:
        # Get release details
        response = await http_client.get(
            f"organizations/{organization}/releases/{version}/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        if response.status_code == 401:
            raise McpError(
                "Error: Unauthorized. Please check your MCP_SENTRY_AUTH_TOKEN token."
            )
        response.raise_for_status()
        release_data = response.json()

        # Get commits for this release
        commits_response = await http_client.get(
            f"organizations/{organization}/releases/{version}/commits/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        commits_response.raise_for_status()
        commits = commits_response.json()

        # Get the latest deployment
        deploys_response = await http_client.get(
            f"organizations/{organization}/releases/{version}/deploys/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        deploys_response.raise_for_status()
        deploys = deploys_response.json()
        last_deploy = deploys[0] if deploys else None

        return SentryReleaseData(
            version=version,
            project=project,
            dateCreated=release_data.get("dateCreated", "Unknown"),
            dateReleased=release_data.get("dateReleased", "Unknown"),
            newGroups=release_data.get("newGroups", 0),
            commits=commits,
            lastDeploy=last_deploy,
            stats=release_data.get("stats", {})
        )

    except httpx.HTTPStatusError as e:
        raise McpError(f"Error fetching Sentry release: {str(e)}")
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
            ),
            types.Prompt(
                name="sentry-transaction",
                description="Retrieve a Sentry transaction/trace by ID",
                arguments=[
                    types.PromptArgument(
                        name="transaction_id",
                        description="Sentry transaction ID",
                        required=True,
                    )
                ],
            ),
            types.Prompt(
                name="sentry-release",
                description="Retrieve information about a Sentry release",
                arguments=[
                    types.PromptArgument(
                        name="organization",
                        description="Sentry organization slug",
                        required=True,
                    ),
                    types.PromptArgument(
                        name="project",
                        description="Sentry project slug",
                        required=True,
                    ),
                    types.PromptArgument(
                        name="version",
                        description="Release version",
                        required=True,
                    ),
                ],
            )
        ]

    @server.get_prompt()
    async def handle_get_prompt(
        name: str, arguments: dict[str, str] | None
    ) -> types.GetPromptResult:
        if name == "sentry-issue":
            issue_id_or_url = (arguments or {}).get("issue_id_or_url", "")
            issue_data = await handle_sentry_issue(http_client, auth_token, issue_id_or_url)
            return issue_data.to_prompt_result()
        elif name == "sentry-transaction":
            transaction_id = (arguments or {}).get("transaction_id", "")
            transaction_data = await handle_sentry_transaction(http_client, auth_token, transaction_id)
            return transaction_data.to_prompt_result()
        elif name == "sentry-release":
            if not arguments:
                raise ValueError("Missing required arguments")
            release_data = await handle_sentry_release(
                http_client,
                auth_token,
                arguments.get("organization", ""),
                arguments.get("project", ""),
                arguments.get("version", "")
            )
            return release_data.to_prompt_result()
        else:
            raise ValueError(f"Unknown prompt: {name}")

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
                name="get_sentry_transaction",
                description="""Retrieve and analyze a Sentry transaction/trace by ID. Use this tool when you need to:
                - Investigate performance issues and slow requests
                - Access detailed transaction traces and spans
                - Analyze request durations and bottlenecks
                - Review transaction status and environment details
                - Get timing information for specific operations""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "transaction_id": {
                            "type": "string",
                            "description": "Sentry transaction ID to analyze"
                        }
                    },
                    "required": ["transaction_id"]
                }
            ),
            types.Tool(
                name="get_sentry_release",
                description="""Retrieve and analyze a Sentry release. Use this tool when you need to:
                - Track deployments and releases
                - View commit information for releases
                - Monitor new issues introduced in releases
                - Check deployment status and environments
                - Review release metrics and statistics""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "organization": {
                            "type": "string",
                            "description": "Sentry organization slug"
                        },
                        "project": {
                            "type": "string",
                            "description": "Sentry project slug"
                        },
                        "version": {
                            "type": "string",
                            "description": "Release version to analyze"
                        }
                    },
                    "required": ["organization", "project", "version"]
                }
            )
        ]

    @server.call_tool()
    async def handle_call_tool(
        name: str, arguments: dict | None
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        if name == "get_sentry_issue":
            if not arguments or "issue_id_or_url" not in arguments:
                raise ValueError("Missing issue_id_or_url argument")
            issue_data = await handle_sentry_issue(http_client, auth_token, arguments["issue_id_or_url"])
            return issue_data.to_tool_result()
        elif name == "get_sentry_transaction":
            if not arguments or "transaction_id" not in arguments:
                raise ValueError("Missing transaction_id argument")
            transaction_data = await handle_sentry_transaction(http_client, auth_token, arguments["transaction_id"])
            return transaction_data.to_tool_result()
        elif name == "get_sentry_release":
            if not arguments:
                raise ValueError("Missing required arguments")
            release_data = await handle_sentry_release(
                http_client,
                auth_token,
                arguments.get("organization", ""),
                arguments.get("project", ""),
                arguments.get("version", "")
            )
            return release_data.to_tool_result()
        else:
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
