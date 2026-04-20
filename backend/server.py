import tempfile
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import List
from dotenv import load_dotenv
from agents import Agent, Runner, trace

from context import SECURITY_RESEARCHER_INSTRUCTIONS, get_analysis_prompt, enhance_summary
from mcp_servers import create_semgrep_server

from openai import AsyncOpenAI
from agents import OpenAIChatCompletionsModel, set_tracing_disabled, set_default_openai_api

load_dotenv(override=True)

set_default_openai_api("chat_completions")
set_tracing_disabled(True)

app = FastAPI(title="Cybersecurity Analyzer API")

cors_origins = [
    "http://localhost:3000",
    "http://frontend:3000",
]

if os.getenv("ENVIRONMENT") == "production":
    cors_origins.append("*")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    code: str


class SecurityIssue(BaseModel):
    title: str = Field(description="Brief title of the security vulnerability")
    description: str = Field(
        description="Detailed description of the security issue and its potential impact"
    )
    code: str = Field(
        description="The specific vulnerable code snippet that demonstrates the issue"
    )
    fix: str = Field(description="Recommended code fix or mitigation strategy")
    cvss_score: float = Field(description="CVSS score from 0.0 to 10.0 representing severity")
    severity: str = Field(description="Severity level: critical, high, medium, or low")


class SecurityReport(BaseModel):
    summary: str = Field(description="Executive summary of the security analysis")
    issues: List[SecurityIssue] = Field(description="List of identified security vulnerabilities")


def validate_request(request: AnalyzeRequest) -> None:
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="No code provided for analysis")


def check_api_keys() -> None:
    if not os.getenv("OPENROUTER_API_KEY"):
        raise HTTPException(status_code=500, detail="OpenRouter API key not configured")
    if not os.getenv("SEMGREP_APP_TOKEN"):
        raise HTTPException(status_code=500, detail="Semgrep app token not configured")


def create_security_agent(semgrep_server) -> Agent:
    base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    api_key = os.getenv("OPENROUTER_API_KEY")
    model_id = os.getenv("OPENROUTER_MODEL", "openai/gpt-4.1-mini").strip("'\"")

    client = AsyncOpenAI(base_url=base_url, api_key=api_key)
    model = OpenAIChatCompletionsModel(openai_client=client, model=model_id)

    return Agent(
        name="Security Researcher",
        instructions=SECURITY_RESEARCHER_INSTRUCTIONS,
        model=model,
        mcp_servers=[semgrep_server],
        output_type=SecurityReport,
    )


async def run_security_analysis(code: str) -> SecurityReport:
    """Execute the security analysis workflow."""
    with trace("Security Researcher"):
        async with create_semgrep_server() as semgrep:
            agent = create_security_agent(semgrep)
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".py", delete=False
                ) as temp:
                    temp.write(code)
                    temp_path = temp.name
                try:
                    result = await Runner.run(
                        agent,
                        input=get_analysis_prompt(code, temp_path),
                    )
                    sorted_report = result.final_output_as(SecurityReport)
                    sorted_report.issues.sort(
                        key=lambda issue: issue.cvss_score, reverse=True
                    )
                    return sorted_report
                finally:
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass
            except Exception as err:
                print(f"Unexpected {err=}, {type(err)=}")
                raise


def format_analysis_response(code: str, report: SecurityReport) -> SecurityReport:
    enhanced_summary = enhance_summary(len(code), report.summary)
    return SecurityReport(summary=enhanced_summary, issues=report.issues)


@app.post("/api/analyze", response_model=SecurityReport)
async def analyze_code(request: AnalyzeRequest) -> SecurityReport:
    """
    Analyze Python code for security vulnerabilities using OpenAI Agents and Semgrep.

    This endpoint combines static analysis via Semgrep with AI-powered security analysis
    to provide comprehensive vulnerability detection and remediation guidance.
    """
    validate_request(request)
    check_api_keys()

    try:
        report = await run_security_analysis(request.code)
        return format_analysis_response(request.code, report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/health")
async def health():
    return {"message": "Cybersecurity Analyzer API"}


if os.path.exists("static"):
    app.mount("/", StaticFiles(directory="static", html=True), name="static")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
