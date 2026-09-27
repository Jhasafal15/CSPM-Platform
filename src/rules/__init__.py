"""
Rules package for AI-Powered CSPM Platform
"""
from .scanner import CloudSecurityScanner
from .base_rule import BaseRule, Severity, Category
from .iam_rules import RuleIamMfa, RuleIamAdmin, RuleIamInactiveCredentials
from .s3_rules import RuleS3Public, RuleS3Encryption, RuleS3Versioning
from .ec2_rules import RuleEc2Ingress, RuleEc2OutdatedAmi, RuleEc2VulnerableSoftware

__all__ = [
    "CloudSecurityScanner",
    "BaseRule",
    "Severity",
    "Category",
    "RuleIamMfa",
    "RuleIamAdmin",
    "RuleIamInactiveCredentials",
    "RuleS3Public",
    "RuleS3Encryption",
    "RuleS3Versioning",
    "RuleEc2Ingress",
    "RuleEc2OutdatedAmi",
    "RuleEc2VulnerableSoftware"
]
