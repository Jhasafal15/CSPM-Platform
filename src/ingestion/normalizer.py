"""
Module 2: Cloud Data Normalizer
Standardizes identifiers, normalizes timestamps, flattens nested policies/security groups,
imputes missing values, and builds the unified structured cloud_inventory.json.
"""

import os
import json
import logging
from datetime import datetime, timezone
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Normalizer")

class CloudDataNormalizer:
    def __init__(self, raw_data: dict, reference_time: datetime = None):
        self.raw_iam = raw_data.get("iam", [])
        self.raw_s3 = raw_data.get("s3", [])
        self.raw_ec2 = raw_data.get("ec2", [])
        self.raw_vpcs = raw_data.get("vpcs", [])
        self.raw_cloudtrail = raw_data.get("cloudtrail", [])
        self.raw_software_df = raw_data.get("software_inventory", pd.DataFrame())
        self.reference_time = reference_time or datetime(2026, 9, 26, 12, 0, 0, tzinfo=timezone.utc)

    def _normalize_timestamp(self, ts_val) -> str:
        """Standardizes timestamps to ISO 8601 UTC string format: YYYY-MM-DDTHH:MM:SSZ."""
        if not ts_val or pd.isna(ts_val):
            return None
        if isinstance(ts_val, datetime):
            if ts_val.tzinfo is None:
                ts_val = ts_val.replace(tzinfo=timezone.utc)
            return ts_val.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            # Parse string
            clean_str = str(ts_val).replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return str(ts_val)

    def _calculate_days_ago(self, ts_str: str) -> int:
        """Returns days between timestamp and reference time."""
        if not ts_str:
            return 9999
        try:
            clean_str = ts_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            diff = self.reference_time - dt
            return max(0, diff.days)
        except Exception:
            return 9999

    def normalize_iam(self) -> dict:
        """Normalizes IAM users and roles, parses policies for wildcards, standardizes MFA."""
        normalized_users = []
        normalized_roles = []

        for item in self.raw_iam:
            res_id = item.get("resource_id", "UNKNOWN")
            arn = item.get("arn", f"arn:aws:iam::123456789012:user/{item.get('name', 'user')}")
            res_type = item.get("type", "USER").upper()
            mfa_active = bool(item.get("mfa_active", False))
            
            created_at = self._normalize_timestamp(item.get("created_at"))
            last_login = self._normalize_timestamp(item.get("last_login"))
            days_inactive = self._calculate_days_ago(last_login) if last_login else self._calculate_days_ago(created_at)

            # Analyze policies for AdministratorAccess or wildcard Action: * / Resource: *
            attached_policies = item.get("attached_policies", [])
            inline_policies = item.get("inline_policies", [])
            
            has_admin_policy = "AdministratorAccess" in attached_policies
            has_wildcard_permission = False
            flattened_statements = []

            for inline in inline_policies:
                doc = inline.get("policy_document", {})
                statements = doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                for stmt in statements:
                    effect = stmt.get("Effect", "")
                    action = stmt.get("Action", [])
                    resource = stmt.get("Resource", [])
                    
                    if isinstance(action, str):
                        action = [action]
                    if isinstance(resource, str):
                        resource = [resource]

                    flattened_statements.append({
                        "policy_name": inline.get("policy_name", "inline"),
                        "effect": effect,
                        "actions": action,
                        "resources": resource
                    })

                    if effect == "Allow":
                        if "*" in action and "*" in resource:
                            has_wildcard_permission = True
                            has_admin_policy = True

            record = {
                "resource_id": res_id,
                "arn": arn,
                "name": item.get("name", "unknown"),
                "type": res_type,
                "mfa_active": mfa_active,
                "created_at": created_at,
                "last_login": last_login,
                "days_since_active": days_inactive,
                "is_inactive_90_days": days_inactive > 90,
                "attached_policies": attached_policies,
                "has_admin_policy": has_admin_policy,
                "has_wildcard_permission": has_wildcard_permission,
                "flattened_statements": flattened_statements,
                "access_keys_count": len(item.get("access_keys", [])),
                "tags": item.get("tags") or {},
                "raw_config": {
                    "mfa_active": mfa_active,
                    "attached_policies": attached_policies,
                    "has_wildcard_permission": has_wildcard_permission,
                    "days_since_active": days_inactive
                }
            }

            if res_type == "USER":
                normalized_users.append(record)
            else:
                normalized_roles.append(record)

        return {"users": normalized_users, "roles": normalized_roles}

    def normalize_s3(self) -> list:
        """Normalizes S3 bucket configurations, public flags, encryption, and ACLs."""
        normalized_buckets = []
        for bucket in self.raw_s3:
            name = bucket.get("bucket_name", "unknown")
            arn = bucket.get("arn", f"arn:aws:s3:::{name}")
            region = bucket.get("region", "us-east-1")
            
            # Evaluate public accessibility
            is_public_flag = bool(bucket.get("is_public", False))
            pab = bucket.get("public_access_block", {})
            pab_blocks_public = (
                pab.get("block_public_acls", False) and
                pab.get("ignore_public_acls", False) and
                pab.get("block_public_policy", False) and
                pab.get("restrict_public_buckets", False)
            )

            # Check ACL grants for global groups (AllUsers, AuthenticatedUsers)
            acl_grants = bucket.get("acl_grants", [])
            has_public_acl = False
            for grant in acl_grants:
                uri = grant.get("uri", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    has_public_acl = True

            # Check bucket policy for wildcard principal
            has_public_policy = False
            bp = bucket.get("bucket_policy")
            if bp and isinstance(bp, dict):
                statements = bp.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                for stmt in statements:
                    if stmt.get("Effect") == "Allow" and (stmt.get("Principal") == "*" or stmt.get("Principal") == {"AWS": "*"}):
                        has_public_policy = True

            # If any indicator is true and public access block is not enforcing, mark public
            is_public = (is_public_flag or has_public_acl or has_public_policy) and not pab_blocks_public

            encryption_enabled = bool(bucket.get("encryption_enabled", False))
            versioning_enabled = bool(bucket.get("versioning_enabled", False))

            normalized_buckets.append({
                "bucket_name": name,
                "arn": arn,
                "region": region,
                "creation_date": self._normalize_timestamp(bucket.get("creation_date")),
                "is_public": is_public,
                "has_public_acl": has_public_acl,
                "has_public_policy": has_public_policy,
                "public_access_block_enabled": pab_blocks_public,
                "encryption_enabled": encryption_enabled,
                "server_side_encryption_algorithm": bucket.get("server_side_encryption_algorithm"),
                "kms_master_key_id": bucket.get("kms_master_key_id"),
                "versioning_enabled": versioning_enabled,
                "logging_enabled": bool(bucket.get("logging_enabled", False)),
                "tags": bucket.get("tags") or {},
                "raw_config": {
                    "is_public": is_public,
                    "encryption_enabled": encryption_enabled,
                    "versioning_enabled": versioning_enabled,
                    "has_public_acl": has_public_acl
                }
            })
        return normalized_buckets

    def normalize_ec2(self) -> list:
        """Normalizes EC2 instances, extracts flattened open ports and ingress security rules, maps software inventory."""
        normalized_instances = []
        
        # Index software inventory by instance_id
        software_by_instance = {}
        if not self.raw_software_df.empty:
            for _, row in self.raw_software_df.iterrows():
                iid = str(row["instance_id"])
                if iid not in software_by_instance:
                    software_by_instance[iid] = []
                software_by_instance[iid].append({
                    "software_name": str(row["software_name"]),
                    "installed_version": str(row["installed_version"]),
                    "is_vulnerable": bool(row["is_vulnerable"]),
                    "cve_id": str(row["cve_id"]),
                    "cve_severity": str(row["cve_severity"])
                })

        for inst in self.raw_ec2:
            iid = inst.get("instance_id", "unknown")
            arn = inst.get("arn", f"arn:aws:ec2:us-east-1:123456789012:instance/{iid}")
            public_ip = inst.get("public_ip")
            if public_ip == "None" or pd.isna(public_ip):
                public_ip = None

            is_outdated_ami = bool(inst.get("is_outdated_ami", False))
            sgs = inst.get("security_groups", [])

            # Flatten security group rules
            open_ports = set()
            internet_exposed_ports = set()
            open_rules_details = []

            for sg in sgs:
                sg_id = sg.get("group_id", "unknown")
                for rule in sg.get("inbound_rules", []):
                    cidr = rule.get("cidr_ip", "")
                    from_port = rule.get("from_port")
                    to_port = rule.get("to_port")
                    protocol = rule.get("protocol", "tcp")

                    if from_port is not None:
                        # Expand or represent port range
                        ports = [from_port] if from_port == to_port else list(range(from_port, min(from_port + 20, (to_port or from_port) + 1)))
                        for p in ports:
                            open_ports.add(p)

                        is_open_to_all = (cidr == "0.0.0.0/0" or cidr == "::/0")
                        if is_open_to_all:
                            for p in ports:
                                internet_exposed_ports.add(p)

                        open_rules_details.append({
                            "security_group_id": sg_id,
                            "protocol": protocol,
                            "from_port": from_port,
                            "to_port": to_port,
                            "cidr_ip": cidr,
                            "is_internet_open": is_open_to_all
                        })

            has_open_ssh = (22 in internet_exposed_ports)
            has_open_rdp = (3389 in internet_exposed_ports)
            has_open_8080 = (8080 in internet_exposed_ports)

            installed_pkgs = software_by_instance.get(iid, [])
            vulnerable_pkgs = [p for p in installed_pkgs if p["is_vulnerable"]]

            normalized_instances.append({
                "instance_id": iid,
                "arn": arn,
                "name": inst.get("name", iid),
                "instance_type": inst.get("instance_type", "t3.medium"),
                "state": inst.get("state", "running"),
                "region": inst.get("region", "us-east-1"),
                "public_ip": public_ip,
                "private_ip": inst.get("private_ip"),
                "vpc_id": inst.get("vpc_id"),
                "subnet_id": inst.get("subnet_id"),
                "ami_id": inst.get("ami_id"),
                "ami_creation_date": self._normalize_timestamp(inst.get("ami_creation_date")),
                "is_outdated_ami": is_outdated_ami,
                "open_ports": sorted(list(open_ports)),
                "internet_exposed_ports": sorted(list(internet_exposed_ports)),
                "has_open_ssh": has_open_ssh,
                "has_open_rdp": has_open_rdp,
                "has_open_8080": has_open_8080,
                "security_group_rules": open_rules_details,
                "software_inventory": installed_pkgs,
                "vulnerable_software_count": len(vulnerable_pkgs),
                "tags": inst.get("tags") or {},
                "raw_config": {
                    "public_ip": public_ip,
                    "open_ports": sorted(list(open_ports)),
                    "internet_exposed_ports": sorted(list(internet_exposed_ports)),
                    "is_outdated_ami": is_outdated_ami
                }
            })
        return normalized_instances

    def normalize_cloudtrail(self) -> list:
        """Normalizes and indexes CloudTrail event logs."""
        normalized_events = []
        for event in self.raw_cloudtrail:
            normalized_events.append({
                "event_id": event.get("eventId"),
                "event_time": self._normalize_timestamp(event.get("eventTime")),
                "event_source": event.get("eventSource"),
                "event_name": event.get("eventName"),
                "aws_region": event.get("awsRegion"),
                "source_ip_address": event.get("sourceIPAddress"),
                "user_name": event.get("userIdentity", {}).get("userName"),
                "user_arn": event.get("userIdentity", {}).get("arn"),
                "error_code": event.get("errorCode"),
                "error_message": event.get("errorMessage"),
                "request_parameters": event.get("requestParameters") or {}
            })
        return normalized_events

    def process_and_save(self, output_filepath: str) -> dict:
        """Executes full normalization and writes data/processed/cloud_inventory.json."""
        logger.info("Normalizing raw cloud inventory datasets...")
        iam_res = self.normalize_iam()
        s3_res = self.normalize_s3()
        ec2_res = self.normalize_ec2()
        ct_res = self.normalize_cloudtrail()

        unified_inventory = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "account_id": "123456789012",
                "total_resources": len(iam_res["users"]) + len(iam_res["roles"]) + len(s3_res) + len(ec2_res) + len(self.raw_vpcs),
                "counts": {
                    "iam_users": len(iam_res["users"]),
                    "iam_roles": len(iam_res["roles"]),
                    "s3_buckets": len(s3_res),
                    "ec2_instances": len(ec2_res),
                    "vpcs": len(self.raw_vpcs),
                    "cloudtrail_events": len(ct_res)
                }
            },
            "iam_users": iam_res["users"],
            "iam_roles": iam_res["roles"],
            "s3_buckets": s3_res,
            "ec2_instances": ec2_res,
            "vpcs": self.raw_vpcs,
            "cloudtrail_events": ct_res
        }

        os.makedirs(os.path.dirname(output_filepath), exist_ok=True)
        with open(output_filepath, "w", encoding="utf-8") as f:
            json.dump(unified_inventory, f, indent=2)

        logger.info(f"Saved normalized inventory ({unified_inventory['metadata']['total_resources']} resources) to {output_filepath}")
        return unified_inventory
