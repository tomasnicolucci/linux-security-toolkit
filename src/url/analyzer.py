from dataclasses import dataclass

from src.url.domain import parse_url
from src.url.rules import Finding, analyze_rules


SEVERITY_WEIGHTS = {
    "LOW": 5,
    "MEDIUM": 15,
    "HIGH": 30,
    "CRITICAL": 50,
}


@dataclass(frozen=True)
class URLAnalysis:
    url: str
    hostname: str
    registered_domain: str | None
    risk_score: int
    risk_level: str
    findings: list[Finding]


def analyze_url(url: str) -> URLAnalysis:
    info = parse_url(url)
    findings = analyze_rules(info)

    score = min(
        sum(
            SEVERITY_WEIGHTS[finding.severity]
            for finding in findings
        ),
        100,
    )

    if score >= 75:
        risk_level = "CRITICAL"
    elif score >= 30:
        risk_level = "HIGH"
    elif score >= 15:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return URLAnalysis(
        url=info.original,
        hostname=info.hostname,
        registered_domain=info.registered_domain,
        risk_score=score,
        risk_level=risk_level,
        findings=findings,
    )
