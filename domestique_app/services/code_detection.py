"""Code and intellectual property detection.

Detects proprietary source code, internal package names, trade secrets,
and sensitive technical information in prompts sent to LLMs.

Architecture:
    - Pattern-based detection for common indicators
    - Configurable org-specific patterns (internal domains, package names)
    - Import path analysis for language-specific detection

Usage:
    from domestique_app.services.code_detection import CodeDetector, OrgConfig

    config = OrgConfig(
        internal_domains=["corp.internal", "git.company.io"],
        package_prefixes=["@company/", "com.company."],
        project_codenames=["ProjectX", "Falcon"],
    )
    detector = CodeDetector(config)
    result = detector.scan("import com.company.secret.api.Client")
    if result.is_sensitive:
        print(f"Code leak: {result.category}")
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class OrgConfig:
    """Organization-specific configuration for code detection.

    Attributes:
        internal_domains: Internal hostnames/domains (e.g., "git.corp.io").
        package_prefixes: Code package prefixes (e.g., "@company/", "com.corp.").
        project_codenames: Secret project names to detect.
        internal_paths: Internal file/URL path patterns.
        ip_ranges: Internal IP address ranges (CIDR notation strings).
    """

    internal_domains: list[str] = field(default_factory=list)
    package_prefixes: list[str] = field(default_factory=list)
    project_codenames: list[str] = field(default_factory=list)
    internal_paths: list[str] = field(default_factory=list)
    ip_ranges: list[str] = field(
        default_factory=lambda: [
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "192.168.",
        ]
    )


@dataclass(frozen=True)
class CodeFinding:
    """A single code/IP detection finding."""

    category: str
    value: str
    start: int
    end: int
    confidence: float
    description: str = ""


@dataclass
class CodeResult:
    """Result of code/IP scanning."""

    is_sensitive: bool
    findings: list[CodeFinding] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)

    @property
    def highest_confidence(self) -> float:
        """Maximum confidence across all findings."""
        if not self.findings:
            return 0.0
        return max(f.confidence for f in self.findings)


# Built-in patterns for common code/IP indicators
_INTERNAL_URL_PATTERN = re.compile(
    r"https?://(?:[\w.-]+\.(?:internal|local|corp|private|intranet|dev)\b"
    r"|localhost(?::\d+)?)"
    r"[/\w.-]*",
    re.IGNORECASE,
)

_PRIVATE_IP_PATTERN = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)

_IMPORT_PATTERNS = [
    # Python imports
    re.compile(r"(?:from|import)\s+([\w.]+)", re.MULTILINE),
    # JavaScript/TypeScript imports
    re.compile(r'(?:import\b.*?from|require)\s*\(?["\'](@?[\w./-][\w./-]*)["\']', re.MULTILINE),
    # Java/Kotlin imports
    re.compile(r"import\s+([\w.]+)", re.MULTILINE),
    # Go imports
    re.compile(r'"([\w./]+)"', re.MULTILINE),
]

_CONNECTION_STRING_PATTERN = re.compile(
    r"(?:(?:jdbc:[\w]+://|mongodb://|redis://|mysql://|postgres(?:ql)?://|amqp://|mssql://)[\w:@./-]+|"
    r"Server=[\w.]+;(?:Database|Initial Catalog)=[\w]+)",
    re.IGNORECASE,
)

_INTERNAL_HOSTNAME_PATTERN = re.compile(
    r"\b[\w-]+\.(?:internal|local|corp|private|intranet|staging|preprod)\b",
    re.IGNORECASE,
)

_FILE_PATH_PATTERN = re.compile(
    r"(?:/(?:opt|srv|var|home|Users)/[\w./-]{10,}|"
    r"[A-Z]:\\(?:Users|Projects|Source)\\[\w.\\/-]{10,})",
)


class CodeDetector:
    """Detects proprietary code and internal infrastructure references.

    Thread-safe, stateless detector. Combine built-in patterns with
    org-specific configuration.

    Args:
        org_config: Organization-specific detection config.
    """

    def __init__(self, org_config: OrgConfig | None = None) -> None:
        self._config = org_config or OrgConfig()
        self._compiled_domains = [
            re.compile(re.escape(d), re.IGNORECASE) for d in self._config.internal_domains
        ]
        self._compiled_codenames = [
            re.compile(r"\b" + re.escape(name) + r"\b", re.IGNORECASE)
            for name in self._config.project_codenames
        ]

    def scan(self, text: str) -> CodeResult:
        """Scan text for code and IP indicators.

        Args:
            text: The text to analyze (may contain code).

        Returns:
            CodeResult with all findings.
        """
        if not text:
            return CodeResult(is_sensitive=False)

        findings: list[CodeFinding] = []

        # Check internal URLs
        findings.extend(self._check_internal_urls(text))

        # Check private IPs
        findings.extend(self._check_private_ips(text))

        # Check internal hostnames
        findings.extend(self._check_internal_hostnames(text))

        # Check import statements for org packages
        findings.extend(self._check_imports(text))

        # Check connection strings
        findings.extend(self._check_connection_strings(text))

        # Check project codenames
        findings.extend(self._check_codenames(text))

        # Check file paths
        findings.extend(self._check_file_paths(text))

        if not findings:
            return CodeResult(is_sensitive=False)

        categories = list({f.category for f in findings})
        return CodeResult(
            is_sensitive=True,
            findings=findings,
            categories=categories,
        )

    def _check_internal_urls(self, text: str) -> list[CodeFinding]:
        """Detect internal/private URLs."""
        findings = []
        for match in _INTERNAL_URL_PATTERN.finditer(text):
            findings.append(
                CodeFinding(
                    category="internal_url",
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.9,
                    description="Internal/private URL detected",
                )
            )
        # Check org-specific domains
        for domain_pattern in self._compiled_domains:
            for match in domain_pattern.finditer(text):
                findings.append(
                    CodeFinding(
                        category="internal_domain",
                        value=match.group(),
                        start=match.start(),
                        end=match.end(),
                        confidence=0.95,
                        description="Organization-specific internal domain",
                    )
                )
        return findings

    def _check_private_ips(self, text: str) -> list[CodeFinding]:
        """Detect private/internal IP addresses."""
        findings = []
        for match in _PRIVATE_IP_PATTERN.finditer(text):
            findings.append(
                CodeFinding(
                    category="private_ip",
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.7,
                    description="Private IP address",
                )
            )
        return findings

    def _check_internal_hostnames(self, text: str) -> list[CodeFinding]:
        """Detect internal hostnames."""
        findings = []
        for match in _INTERNAL_HOSTNAME_PATTERN.finditer(text):
            findings.append(
                CodeFinding(
                    category="internal_hostname",
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.8,
                    description="Internal hostname pattern",
                )
            )
        return findings

    def _check_imports(self, text: str) -> list[CodeFinding]:
        """Detect imports of org-specific packages."""
        if not self._config.package_prefixes:
            return []

        findings = []
        for pattern in _IMPORT_PATTERNS:
            for match in pattern.finditer(text):
                import_path = match.group(1)
                for prefix in self._config.package_prefixes:
                    if import_path.startswith(prefix):
                        findings.append(
                            CodeFinding(
                                category="proprietary_import",
                                value=import_path,
                                start=match.start(),
                                end=match.end(),
                                confidence=0.95,
                                description=f"Import of internal package ({prefix}...)",
                            )
                        )
                        break
        return findings

    def _check_connection_strings(self, text: str) -> list[CodeFinding]:
        """Detect database/service connection strings."""
        findings = []
        for match in _CONNECTION_STRING_PATTERN.finditer(text):
            findings.append(
                CodeFinding(
                    category="connection_string",
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.9,
                    description="Database/service connection string",
                )
            )
        return findings

    def _check_codenames(self, text: str) -> list[CodeFinding]:
        """Detect project codenames."""
        findings = []
        for pattern in self._compiled_codenames:
            for match in pattern.finditer(text):
                findings.append(
                    CodeFinding(
                        category="project_codename",
                        value=match.group(),
                        start=match.start(),
                        end=match.end(),
                        confidence=0.85,
                        description="Internal project codename",
                    )
                )
        return findings

    def _check_file_paths(self, text: str) -> list[CodeFinding]:
        """Detect internal file system paths."""
        findings = []
        for match in _FILE_PATH_PATTERN.finditer(text):
            findings.append(
                CodeFinding(
                    category="file_path",
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.6,
                    description="Internal file system path",
                )
            )
        return findings
