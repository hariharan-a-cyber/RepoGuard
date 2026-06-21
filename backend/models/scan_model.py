from datetime import datetime
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class ScanRequest(BaseModel):
    github_url: str = Field(..., description="Public GitHub repository URL")
    language: str = Field(default="auto", description="Language target: nodejs, python, or auto-detect.")
    strict_mode: bool = Field(default=False, description="Enable high-recall scanning with relaxed suppression")
    quick_mode: bool = Field(default=False, description="Enable faster scan mode for large repositories")

    @field_validator("language", mode="before")
    @classmethod
    def _validate_language(cls, value: str) -> str:
        normalized = str(value or "auto").strip().lower()
        if normalized in {"nodejs", "node.js", "javascript", "js", "typescript", "ts"}:
            return "nodejs"
        if normalized in {"python", "py"}:
            return "python"
        return "auto"


class StartScanResponse(BaseModel):
    scan_id: str
    status: str = "pending"


class AIGuidance(BaseModel):
    explanation: str
    danger: str
    real_world_example: str
    exact_fix: str
    confidence: str = "Medium"
    guidance_type: str = "template-only"
    fallback_reason: Optional[str] = None


class SecurityIssue(BaseModel):
    title: str = Field(..., min_length=1)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    finding_type: str = "code_vuln"
    file: str = Field(..., min_length=1)
    line: int = Field(..., ge=1)
    snippet: str = ""
    scanner: str = Field(..., min_length=1)
    rule_id: str = Field(..., min_length=1)
    message: str = Field(..., min_length=1)
    fix_description: Optional[str] = None
    fix_code: Optional[str] = None
    category: str = "Weak Input Validation"
    data_source: str = "internal"
    usage_context: str = "unknown"
    evidence: str = ""
    occurrence_count: int = Field(default=1, ge=1)
    confidence: int = Field(default=70, ge=0, le=100)
    confidence_label: Literal["HIGH", "MEDIUM", "LOW"] = "MEDIUM"
    confidence_reasons: List[str] = Field(default_factory=list, max_length=5)
    attention_level: Literal["HIGH", "MEDIUM", "LOW"] = "MEDIUM"
    exploit_scenario: List[str] = Field(default_factory=list, max_length=5)
    package: Optional[str] = None
    package_version: Optional[str] = None
    cve: Optional[str] = None
    fix_version: Optional[str] = None
    framework: Optional[str] = None
    route_hint: Optional[str] = None
    source_symbol: Optional[str] = None
    sink_symbol: Optional[str] = None
    exploitability: Literal["REMOTE", "AUTHENTICATED", "LOCAL_ONLY", "UNKNOWN", "reachable", "unreachable", "unknown"] = "UNKNOWN"
    exploitability_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    exploitability_label: Literal["LIKELY", "POSSIBLY", "UNCLEAR"] = "UNCLEAR"
    exploitability_level: Optional[Literal["HIGH", "MEDIUM", "LOW"]] = None
    estimated_fix_time_minutes: Optional[int] = Field(default=None, ge=1, le=240)
    impact_summary: Optional[str] = None
    impact_code: Optional[str] = None
    fix_command: Optional[str] = None
    cli_output: Optional[str] = None
    api_output: Optional[Dict[str, str]] = None
    poc_payload: Optional[str] = None
    poc_command: Optional[str] = None
    poc_snippet: Optional[str] = None
    propagation_depth: int = Field(default=0, ge=0, le=2)
    propagation_chain: List[str] = Field(default_factory=list, max_length=5)
    guidance: AIGuidance

    @field_validator("title", "file", "scanner", "rule_id", "message", mode="before")
    @classmethod
    def _strip_non_empty(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("field must be non-empty")
        return text

    @field_validator("exploit_scenario")
    @classmethod
    def _validate_exploit_steps(cls, value: List[str]) -> List[str]:
        cleaned = [str(step or "").strip() for step in value]
        if any(not step for step in cleaned):
            raise ValueError("exploit scenario steps must be non-empty")
        return cleaned

    @field_validator("propagation_chain")
    @classmethod
    def _validate_propagation_chain(cls, value: List[str]) -> List[str]:
        cleaned = [str(step or "").strip() for step in value]
        if any(not step for step in cleaned):
            raise ValueError("propagation chain steps must be non-empty")
        return cleaned


class ScanResponse(BaseModel):
    scan_id: str
    timestamp: datetime
    github_url: str
    repo_name: str = "repository"
    issue_count: int
    risk_score: int
    issues: List[SecurityIssue]
    priority_issues: List[SecurityIssue] = Field(default_factory=list)
    file_summary: Dict[str, int] = Field(default_factory=dict)
    score_breakdown: Dict[str, int] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)
    plan: str = "free"
    is_limited: bool = False
    visible_issue_count: Optional[int] = None
    total_issue_count: Optional[int] = None
    locked_issue_count: Optional[int] = None
    upgrade_message: Optional[str] = None
    files_scanned: int = 0
    patterns_checked: int = 0
    ai_calls_made: int = 0
    ai_calls_budget: int = 0
    critical_issue_count: int = 0
    low_issue_count: int = 0
    has_critical_issues: bool = False
    scan_effort_valid: bool = False
    insufficient_coverage: bool = False
    coverage_message: Optional[str] = None
    strict_mode: bool = False
    quick_mode: bool = False
    aggregate_risk_label: Optional[str] = None
    aggregate_risk_explainer: Optional[str] = None
    access_tier: str = "free"
    audit_unlocked: bool = False
    analyzer_capabilities: Dict[str, bool] = Field(default_factory=dict)
    detected_frameworks: List[str] = Field(default_factory=list)


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    message: Optional[str] = None
    stage: Optional[str] = None
    retry_count: int = 0
    report: Optional[ScanResponse] = None


class ScanHistoryItem(BaseModel):
    scan_id: str
    timestamp: datetime
    github_url: str
    risk_score: int
    issue_count: int


class UserAuthRequest(BaseModel):
    email: str
    password: str


class AuthSessionResponse(BaseModel):
    token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 900
    email: str
    plan: str
    scans_remaining_today: int
    unlocked_scan_count: int = 0


class AuthRefreshRequest(BaseModel):
    refresh_token: Optional[str] = Field(default=None, min_length=10)


class AuthLogoutRequest(BaseModel):
    refresh_token: Optional[str] = None


class AuthMeResponse(BaseModel):
    email: str
    plan: str
    scans_remaining_today: int
    unlocked_scan_count: int = 0


class GoogleOneTapRequest(BaseModel):
    credential: str = Field(..., min_length=10)


class GoogleOneTapConfigResponse(BaseModel):
    enabled: bool = False
    client_id: Optional[str] = None


class AuditUnlockRequest(BaseModel):
    scan_id: str = Field(..., min_length=1)


class FirebaseSignInRequest(BaseModel):
    idToken: str = Field(..., min_length=10)


class FirebaseConfigResponse(BaseModel):
    enabled: bool = False
    apiKey: Optional[str] = None
    authDomain: Optional[str] = None
    projectId: Optional[str] = None
    appId: Optional[str] = None


class AuditUnlockResponse(BaseModel):
    status: str = "ok"
    scan_id: str
    access_tier: str = "audit"


class FeedbackRequest(BaseModel):
    scan_id: str = Field(..., min_length=1)
    rating: int = Field(..., ge=1, le=5)
    category: Literal["false_positive", "missing", "unhelpful", "general"]
    comment: str = Field(..., min_length=3, max_length=1000)
    issue_id: Optional[str] = Field(default=None, max_length=200)

    @field_validator("comment", mode="before")
    @classmethod
    def _validate_trimmed_comment(cls, value: str) -> str:
        text = str(value or "").strip()
        if len(text) < 3:
            raise ValueError("comment must be at least 3 non-space characters")
        return text


class FeedbackItem(BaseModel):
    feedback_id: str
    email: str
    scan_id: str
    rating: int = Field(..., ge=1, le=5)
    category: Literal["false_positive", "missing", "unhelpful", "general"]
    comment: str
    issue_id: Optional[str] = None
    created_at: datetime


class FeedbackResponse(BaseModel):
    status: str = "ok"
    item: FeedbackItem


class UserMetricsResponse(BaseModel):
    email: str
    scans_started: int = 0
    scans_completed: int = 0
    unlock_clicked: int = 0
    audit_unlocked: int = 0


class CohortMetricsResponse(BaseModel):
    total_events: int = 0
    unique_users: int = 0
    scans_started: int = 0
    scans_completed: int = 0
    unlock_clicked: int = 0
    audit_unlocked: int = 0


class AnalyticsSummaryResponse(BaseModel):
    generated_at: datetime
    cohort: CohortMetricsResponse
    cohort_24h: CohortMetricsResponse
    cohort_7d: CohortMetricsResponse
    completion_rate: float = 0.0
    completion_rate_24h: float = 0.0
    completion_rate_7d: float = 0.0
    unlock_click_through_rate: float = 0.0
    unlock_click_through_rate_24h: float = 0.0
    unlock_click_through_rate_7d: float = 0.0
    unlock_conversion_rate: float = 0.0
    unlock_conversion_rate_24h: float = 0.0
    unlock_conversion_rate_7d: float = 0.0


class ValidationRunRequest(BaseModel):
    manifest_id: Optional[str] = Field(
        default=None,
        description="The ID of the validation manifest to run (e.g., 'pinned_manifest').",
    )
    manifest_path: Optional[str] = Field(
        default=None,
        description="Optional absolute/relative path to a manifest JSON file.",
    )
    output_dir: Optional[str] = Field(
        default=None,
        description="Optional directory where validation artifacts are written.",
    )


class ValidationRepoResult(BaseModel):
    repo_id: str
    repo_path: str
    expected_issue_count: int
    actual_issue_count: int
    issue_tolerance: int
    issue_delta: int
    expected_high_count: int
    actual_high_count: int
    high_tolerance: int
    high_delta: int
    passed: bool


class ValidationRunResponse(BaseModel):
    status: str = "ok"
    run_id: str
    generated_at: datetime
    manifest_path: str
    artifact_path: str
    total_repos: int
    passed_repos: int
    failed_repos: int
    results: List[ValidationRepoResult]


class ValidationLatestArtifactResponse(BaseModel):
    status: str = "ok"
    artifact_path: str
    run_id: str
    generated_at: datetime
    manifest_path: str
    total_repos: int
    passed_repos: int
    failed_repos: int
