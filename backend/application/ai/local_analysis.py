"""Bounded facts for optional local LLM and cloud demo interpretation of stored evidence."""

from datetime import datetime, timezone
import json

from ...domain.security import (AuthorizationAction, AuthorizationRequest,
                                AuthorizationResource, PrincipalType)
from ..organization.context import OrganizationContext
from .offline_rules import build_offline_fix_plan, reorder_plan_with_model_refs
from .synthetic_demo import (
    CANONICAL_DEMO_REFS,
    DEMO_REF_TO_FINDING_ID,
    WINDOWS_HARDENING_DEMO_ID,
    build_synthetic_windows_demo_report,
    get_demo_source_descriptor,
)


class TenantLocalAnalysisService:
    def __init__(self, report_service, authorizer, provider, *, cloud_provider=None, clock=None,
                 max_prompt_chars=12000, max_finding_facts=30):
        if not 2000 <= max_prompt_chars <= 12000 or max_finding_facts <= 0:
            raise ValueError("invalid local analysis bounds")
        self.reports = report_service
        self.authorizer = authorizer
        self.provider = provider
        self.cloud_provider = cloud_provider
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.max_prompt_chars = max_prompt_chars
        self.max_finding_facts = max_finding_facts

    def analyze(self, principal, context, *, endpoint_id=None, assessment_ids=None,
                demo_id=None, model=None, offline_plan: bool = False):
        if principal.principal_type is not PrincipalType.HUMAN or not isinstance(context, OrganizationContext):
            raise PermissionError("human organization context required")

        allowed_models = {"lm_studio", "offline", "gemini"}
        if model is not None and model not in allowed_models:
            raise ValueError(f"unsupported AI model: {model}")

        if demo_id is not None:
            if endpoint_id is not None or assessment_ids is not None:
                raise ValueError("demo_id is mutually exclusive with endpoint_id and assessment_ids")
            if demo_id != WINDOWS_HARDENING_DEMO_ID:
                raise ValueError(f"unsupported demo_id: {demo_id}")

        # Enforce human membership, ai.use and reports.read on both real and demo requests
        decision = self.authorizer.authorize(AuthorizationRequest(
            principal, AuthorizationAction.AI_USE,
            AuthorizationResource("local_ai_analysis", metadata={"organization_id": str(context.organization_id)}),
            organization_context=context))
        if not decision.allowed:
            raise PermissionError(decision.reason_code)

        read_decision = self.authorizer.authorize(AuthorizationRequest(
            principal, AuthorizationAction.REPORT_READ,
            AuthorizationResource("fleet_report", metadata={"organization_id": str(context.organization_id)}),
            organization_context=context))
        if not read_decision.allowed:
            raise PermissionError(read_decision.reason_code)

        if model == "gemini" and demo_id is None and not getattr(self.cloud_provider, "live_enabled", False):
            raise ValueError("Live Gemini analysis is disabled")

        if demo_id == WINDOWS_HARDENING_DEMO_ID:
            report = build_synthetic_windows_demo_report()
            source = get_demo_source_descriptor(demo_id)
        else:
            report = self.reports.build(principal, context, endpoint_id=endpoint_id,
                                        assessment_ids=assessment_ids)
            source = {
                "organization_id": report["organization_id"],
                "assessment_ids": [row["latest_assessment"]["assessment_id"] for row in report["endpoints"]
                                   if row["latest_assessment"] is not None],
                "endpoint_ids": [row["endpoint_id"] for row in report["endpoints"]],
                "report_generated_at": report["generated_at"],
            }
            if report["summary"]["scanned"] + report["summary"]["partial"] == 0:
                return {"status": "unavailable", "reason_code": "NO_COMPLETED_EVIDENCE",
                        "advisory": True, "analysis": None, "source": source}

        if model == "offline":
            return self._offline_fix_plan(report, source)

        if model == "gemini":
            return self._gemini_fix_plan(report, source, demo_id=demo_id)

        if model == "lm_studio":
            return self._fix_plan(report, source)

        # Legacy mode (model is None / omitted)
        if offline_plan or demo_id is not None:
            return self._fix_plan(report, source)

        # Legacy behavior when model is None and offline_plan is False/omitted on real endpoints
        if not self.provider.enabled:
            return {"status": "unavailable", "reason_code": "LOCAL_AI_DISABLED",
                    "advisory": True, "analysis": None, "source": source}
        facts, coverage = self._facts(report)
        if coverage["included_endpoints"] == 0:
            return {"status": "unavailable", "reason_code": "NO_COMPLETED_EVIDENCE",
                    "advisory": True, "analysis": None, "source": source,
                    "coverage": coverage}
        try:
            output = self.provider.analyze(facts)
        except Exception:
            return {"status": "unavailable", "reason_code": "LOCAL_AI_UNAVAILABLE",
                    "advisory": True, "analysis": None, "source": source,
                    "coverage": coverage}
        return {"status": "available", "reason_code": None, "advisory": True,
                "analysis": output, "model": self.provider.model,
                "provider": "lm_studio", "requested_model": "lm_studio",
                "fallback_used": False, "fallback_reason": None,
                "generated_at": self.clock().astimezone(timezone.utc).isoformat(),
                "source": source, "coverage": coverage,
                "notice": "AI interpretation is advisory; stored assessment evidence is the source of truth."}

    def _offline_fix_plan(self, report, source):
        plan = build_offline_fix_plan(report)
        findings = plan["plan"]
        scanned_count = report["summary"]["scanned"] + report["summary"]["partial"]
        return {
            "status": "available",
            "reason_code": None,
            "advisory": True,
            "analysis": plan["analysis"],
            "model": "Offline rules",
            "provider": "offline",
            "requested_model": "offline",
            "fallback_used": False,
            "fallback_reason": None,
            "generated_at": self.clock().astimezone(timezone.utc).isoformat(),
            "source": source,
            "coverage": {
                "scanned_endpoints": scanned_count,
                "included_endpoints": scanned_count,
                "included_findings": len(findings),
                "truncated": plan["findings_omitted"] > 0,
            },
            "plan": plan["plan"],
            "blind_spots": plan["blind_spots"],
            "out_of_scope_checks": plan["out_of_scope_checks"],
            "notice": "Review recommendations against the source assessment evidence before taking action.",
        }

    def _gemini_fix_plan(self, report, source, *, demo_id):
        plan = build_offline_fix_plan(report)
        findings = plan["plan"]
        scanned_count = report["summary"]["scanned"] + report["summary"]["partial"]
        ranked = None
        fallback_used = False
        fallback_reason = None

        if demo_id is None:
            if findings:
                try:
                    candidates = findings[:min(30, self.max_finding_facts)]
                    categories = [(item["scanner_id"], item["severity"]) for item in candidates]
                    keys = {f"f{i}": item["finding_key"] for i, item in enumerate(candidates, start=1)}
                    refs = self.cloud_provider.prioritize_live_findings(categories)
                    if not isinstance(refs, list) or len(refs) != len(keys) or set(refs) != keys.keys():
                        raise ValueError("Cloud model returned an invalid finding order")
                    ranked = [keys[ref] for ref in refs]
                except Exception:
                    fallback_used = True
                    fallback_reason = "Gemini could not prioritize the findings. Try again or use the local model."
        elif not self.cloud_provider or not self.cloud_provider.enabled:
            fallback_used = True
            fallback_reason = "Gemini cloud demo inference is disabled"
        else:
            try:
                # 1. Resolve each stable fixture finding_id to a unique plan finding_key
                finding_id_to_key = {}
                for item in findings:
                    fid = item.get("finding_id")
                    if not fid or fid in finding_id_to_key:
                        raise ValueError("Duplicate or missing finding_id in plan")
                    finding_id_to_key[fid] = item["finding_key"]

                # 2. Use the fixture's explicit ref-to-finding-ID mapping
                ref_to_key = {}
                for ref, expected_fid in DEMO_REF_TO_FINDING_ID.items():
                    if expected_fid not in finding_id_to_key:
                        raise ValueError(f"Fixture finding_id '{expected_fid}' not found in offline plan")
                    ref_to_key[ref] = finding_id_to_key[expected_fid]

                if len(ref_to_key) != len(CANONICAL_DEMO_REFS):
                    raise ValueError("Fixture ref-to-key mapping incomplete")

                # 3. Call cloud provider to prioritize
                ranked_refs = self.cloud_provider.prioritize_synthetic_demo(fixture_id=demo_id)

                # 4. Strictly validate permutation
                if not isinstance(ranked_refs, list) or len(ranked_refs) != len(CANONICAL_DEMO_REFS):
                    raise ValueError("Cloud model returned incomplete permutation")
                if len(set(ranked_refs)) != len(ranked_refs):
                    raise ValueError("Cloud model returned duplicate references")
                if set(ranked_refs) != set(CANONICAL_DEMO_REFS):
                    raise ValueError("Cloud model returned unknown or invented references")

                # 5. Map ranked_refs to finding_keys without incidental filters
                ranked = []
                for r in ranked_refs:
                    if r not in ref_to_key:
                        raise ValueError(f"Unmatched ref '{r}'")
                    ranked.append(ref_to_key[r])

                if len(ranked) != len(findings):
                    raise ValueError("Permutation size mismatch with plan findings")

            except (ValueError, TypeError) as err:
                ranked = None
                fallback_used = True
                fallback_reason = str(err) if str(err) else "Cloud model returned incomplete permutation"
            except Exception as err:
                ranked = None
                fallback_used = True
                fallback_reason = "Cloud model inference unavailable or timed out"

        if ranked:
            plan = reorder_plan_with_model_refs(plan, ranked, scanned_count)

        actual_model = self.cloud_provider.model if (ranked and not fallback_used) else "Offline rules"
        actual_provider = "google_cloud" if (ranked and not fallback_used) else "offline"

        return {
            "status": "available",
            "reason_code": None,
            "advisory": True,
            "analysis": plan["analysis"],
            "model": actual_model,
            "provider": actual_provider,
            "requested_model": "gemini-3.5-flash-lite",
            "fallback_used": fallback_used,
            "fallback_reason": fallback_reason,
            "generated_at": self.clock().astimezone(timezone.utc).isoformat(),
            "source": source,
            "coverage": {
                "scanned_endpoints": scanned_count,
                "included_endpoints": scanned_count,
                "included_findings": len(findings),
                "truncated": plan["findings_omitted"] > 0,
            },
            "plan": plan["plan"],
            "blind_spots": plan["blind_spots"],
            "out_of_scope_checks": plan["out_of_scope_checks"],
            "notice": "Review recommendations against the source assessment evidence before taking action.",
        }

    def _fix_plan(self, report, source):
        plan = build_offline_fix_plan(report)
        findings = plan["plan"]
        scanned_count = report["summary"]["scanned"] + report["summary"]["partial"]
        ranked = None
        fallback_used = False
        fallback_reason = None

        if not self.provider.enabled:
            fallback_used = bool(findings)
            fallback_reason = "Local inference runtime is disabled" if findings else None
        elif findings:
            ranked = self._prioritized_refs(findings)
            if not ranked:
                fallback_used = True
                fallback_reason = "Local inference runtime unavailable or returned invalid output"

        if ranked:
            plan = reorder_plan_with_model_refs(plan, ranked, scanned_count)

        actual_model = self.provider.model if ranked else "Offline rules"
        actual_provider = "lm_studio" if ranked else "offline"

        return {
            "status": "available",
            "reason_code": None,
            "advisory": True,
            "analysis": plan["analysis"],
            "model": actual_model,
            "provider": actual_provider,
            "requested_model": "lm_studio",
            "fallback_used": fallback_used,
            "fallback_reason": fallback_reason,
            "generated_at": self.clock().astimezone(timezone.utc).isoformat(),
            "source": source,
            "coverage": {
                "scanned_endpoints": scanned_count,
                "included_endpoints": scanned_count,
                "included_findings": len(findings),
                "truncated": plan["findings_omitted"] > 0,
            },
            "plan": plan["plan"],
            "blind_spots": plan["blind_spots"],
            "out_of_scope_checks": plan["out_of_scope_checks"],
            "notice": "Review recommendations against the source assessment evidence before taking action.",
        }

    def _prioritized_refs(self, findings):
        # Keep prompt references short so the model can return the full order within its token budget.
        bound = {}
        items = []
        for index, finding in enumerate(findings[:self.max_finding_facts], start=1):
            ref = f"f{index}"
            item = {"ref": ref, **{key: finding[key] for key in ("severity", "title", "details", "hostname")}}
            candidate = json.dumps({"findings": [*items, item]}, ensure_ascii=True, separators=(",", ":"))
            if len(candidate) > self.max_prompt_chars:
                break
            items.append(item)
            bound[ref] = finding["finding_key"]
        if not items:
            return None

        prompt = json.dumps({"findings": items}, ensure_ascii=True, separators=(",", ":"))
        try:
            content = self.provider.prioritize_findings(prompt).strip()
            lines = content.splitlines()
            if len(lines) >= 3 and lines[0].lower() in {"```", "```json"} and lines[-1] == "```":
                content = "\n".join(lines[1:-1])
            refs = json.loads(content)
        except Exception:
            return None

        if (not isinstance(refs, list) or not refs
                or not all(isinstance(ref, str) and ref in bound for ref in refs)
                or len(refs) != len(set(refs))):
            return None
        return [bound[ref] for ref in refs]

    def _facts(self, report):
        facts = {"summary": report["summary"], "scanned_endpoints": []}
        scanned_count = 0
        for row in report["endpoints"]:
            if row["scan_status"] not in {"scanned", "partial"}:
                continue
            scanned_count += 1
            item = {"endpoint_id": row["endpoint_id"], "hostname": row["hostname"],
                    "assessment_id": row["latest_assessment"]["assessment_id"],
                    "completed_at": row["latest_assessment"]["completed_at"],
                    "scan_status": row["scan_status"], "scanner_results": row["scanner_results"],
                    "finding_count": row["findings_count"], "findings": []}
            for finding in row["findings"]:
                if sum(len(existing["findings"]) for existing in facts["scanned_endpoints"]) + len(item["findings"]) >= self.max_finding_facts:
                    break
                item["findings"].append({key: finding[key] for key in
                                         ("finding_id", "severity", "title", "description", "scanner_id", "evidence")})
            while item["findings"]:
                candidate = facts["scanned_endpoints"] + [item]
                encoded = json.dumps({**facts, "scanned_endpoints": candidate}, ensure_ascii=True,
                                     separators=(",", ":"))
                if len(encoded) <= self.max_prompt_chars:
                    break
                item["findings"].pop()
            candidate = facts["scanned_endpoints"] + [item]
            encoded = json.dumps({**facts, "scanned_endpoints": candidate}, ensure_ascii=True,
                                 separators=(",", ":"))
            if len(encoded) > self.max_prompt_chars:
                break
            facts["scanned_endpoints"] = candidate
        encoded = json.dumps(facts, ensure_ascii=True, separators=(",", ":"))
        coverage = {"scanned_endpoints": scanned_count,
                    "included_endpoints": len(facts["scanned_endpoints"]),
                    "included_findings": sum(len(item["findings"]) for item in facts["scanned_endpoints"]),
                    "truncated": len(facts["scanned_endpoints"]) < scanned_count or
                    sum(row["findings_count"] for row in report["endpoints"]
                        if row["scan_status"] in {"scanned", "partial"}) >
                    sum(len(item["findings"]) for item in facts["scanned_endpoints"])}
        return encoded, coverage
