"""Human-only, organization-scoped fleet reports and advisory local analysis."""

import asyncio
import csv
import json
from dataclasses import dataclass
from io import StringIO
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response

from ..application.identity.service import AuthenticationFailure
from ..application.organization.context import OrganizationContextError


@dataclass(frozen=True)
class TenantInsightsDependencies:
    session_authenticator: object
    user_repository: object
    context_resolver: object
    report_service: object
    analysis_service: object


def create_tenant_insights_router(dependencies: TenantInsightsDependencies) -> APIRouter:
    router = APIRouter()

    def authenticate_human(authorization: Optional[str] = Header(default=None)):
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            raise _error(401, "INVALID_SESSION", "human authentication failed")
        token = authorization[7:].strip()
        if not token or any(character.isspace() for character in token):
            raise _error(401, "INVALID_SESSION", "human authentication failed")
        try:
            principal = dependencies.session_authenticator.authenticate_bearer(token)
            session = dependencies.user_repository.get_session_for_token(token)
        except (AuthenticationFailure, ValueError, KeyError):
            raise _error(401, "INVALID_SESSION", "human authentication failed")
        if session is None:
            raise _error(401, "INVALID_SESSION", "human authentication failed")
        return principal

    def organization_context(organization_id: str, principal=Depends(authenticate_human)):
        try:
            context = dependencies.context_resolver.resolve(principal, organization_id)
        except (OrganizationContextError, ValueError, KeyError):
            raise _error(403, "ORGANIZATION_ACCESS_DENIED", "organization context is unavailable")
        return principal, context

    @router.get("/organizations/{organization_id}/reports/fleet", tags=["Tenant Reports"])
    def fleet_report(assessment_id: list[str] | None = Query(default=None),
                     human=Depends(organization_context)):
        principal, context = human
        return _report_response(dependencies.report_service, principal, context,
                                assessment_ids=assessment_id)

    @router.get("/organizations/{organization_id}/reports/fleet.csv", tags=["Tenant Reports"])
    def fleet_report_csv(assessment_id: list[str] | None = Query(default=None),
                         human=Depends(organization_context)):
        principal, context = human
        report = _build_report(dependencies.report_service, principal, context,
                               assessment_ids=assessment_id)
        output = StringIO()
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow(("endpoint_id", "hostname", "platform", "lifecycle_status", "approved",
                         "presence_state", "last_seen_at", "selected_for_report", "scan_status",
                         "assessment_id", "assessment_status", "requested_at", "completed_at",
                         "last_successful_assessment_at", "findings_count", "scanner_statuses"))
        for row in report["endpoints"]:
            latest = row["latest_assessment"] or {}
            writer.writerow(tuple(_csv_cell(value) for value in (
                row["endpoint_id"], row["hostname"], row["platform"], row["lifecycle_status"],
                row["approved"], row["presence_state"], row["last_seen_at"],
                row["selected_for_report"], row["scan_status"], latest.get("assessment_id"),
                latest.get("status"), latest.get("requested_at"), latest.get("completed_at"),
                row["last_successful_assessment_at"], row["findings_count"],
                "; ".join(f'{item["scanner_id"]}:{item["status"]}' for item in row["scanner_results"]))))
        return Response("\ufeff" + output.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Cache-Control": "no-store",
                                 "Content-Disposition": 'attachment; filename="ravenx-fleet-report.csv"'})

    @router.get("/organizations/{organization_id}/endpoints/{endpoint_id}/report", tags=["Tenant Reports"])
    def endpoint_report(endpoint_id: str, assessment_id: list[str] | None = Query(default=None),
                        human=Depends(organization_context)):
        principal, context = human
        return _report_response(dependencies.report_service, principal, context,
                                endpoint_id=endpoint_id, assessment_ids=assessment_id)

    @router.get("/organizations/{organization_id}/reports/fleet.pdf", tags=["Tenant Reports"])
    def fleet_report_pdf(assessment_id: list[str] | None = Query(default=None),
                         human=Depends(organization_context)):
        principal, context = human
        return _pdf_response(dependencies.report_service, principal, context, assessment_ids=assessment_id)

    @router.get("/organizations/{organization_id}/endpoints/{endpoint_id}/report.pdf", tags=["Tenant Reports"])
    def endpoint_report_pdf(endpoint_id: str, assessment_id: list[str] | None = Query(default=None),
                            human=Depends(organization_context)):
        principal, context = human
        return _pdf_response(dependencies.report_service, principal, context,
                             endpoint_id=endpoint_id, assessment_ids=assessment_id)

    @router.post("/organizations/{organization_id}/ai/analyze", tags=["Local AI"])
    async def analyze(request: Request, human=Depends(organization_context)):
        if request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
            raise _error(415, "UNSUPPORTED_MEDIA_TYPE", "application/json is required")
        maximum = 16 * 1024
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                size = int(declared)
                if size < 0:
                    raise ValueError("negative content length")
                if size > maximum:
                    raise _error(413, "PAYLOAD_TOO_LARGE", "analysis selection is too large")
            except ValueError:
                raise _error(400, "MALFORMED_REQUEST", "invalid content length")
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > maximum:
                raise _error(413, "PAYLOAD_TOO_LARGE", "analysis selection is too large")
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise _error(400, "MALFORMED_JSON", "request body is not valid JSON")
        if (not isinstance(body, dict) or set(body) - {"endpoint_id", "assessment_ids", "offline_plan"}
                or (body.get("endpoint_id") is not None and not isinstance(body["endpoint_id"], str))
                or (body.get("assessment_ids") is not None and
                    (not isinstance(body["assessment_ids"], list) or
                     not all(isinstance(value, str) for value in body["assessment_ids"])))
                or ("offline_plan" in body and type(body["offline_plan"]) is not bool)):
            raise _error(422, "INVALID_REQUEST", "invalid analysis selection")
        principal, context = human
        try:
            result = await asyncio.to_thread(
                dependencies.analysis_service.analyze, principal, context,
                endpoint_id=body.get("endpoint_id"), assessment_ids=body.get("assessment_ids"),
                offline_plan=bool(body.get("offline_plan", False)))
        except PermissionError:
            raise _error(403, "FORBIDDEN", "permission denied")
        except KeyError:
            raise _error(404, "NOT_FOUND", "resource not found")
        except ValueError:
            raise _error(422, "INVALID_REQUEST", "invalid analysis selection")
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    return router


def _report_response(service, principal, context, **selection):
    return JSONResponse(_build_report(service, principal, context, **selection),
                        headers={"Cache-Control": "no-store"})


def _pdf_response(service, principal, context, **selection):
    report = _build_report(service, principal, context, **selection)
    from ..application.reporting.fleet_pdf import render_fleet_pdf

    kind = "machine" if report["scope"]["kind"] == "endpoint" else "fleet"
    return Response(render_fleet_pdf(report), media_type="application/pdf", headers={
        "Cache-Control": "no-store",
        "Content-Disposition": f'attachment; filename="ravenx-{kind}-report.pdf"',
    })


def _build_report(service, principal, context, **selection):
    try:
        result = service.build(principal, context, **selection)
    except PermissionError:
        raise _error(403, "FORBIDDEN", "permission denied")
    except KeyError:
        raise _error(404, "NOT_FOUND", "resource not found")
    except ValueError:
        raise _error(422, "INVALID_REQUEST", "invalid report selection")
    return result


def _csv_cell(value):
    text = "" if value is None else str(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text


def _error(status_code, code, message):
    return HTTPException(status_code=status_code, detail={"code": code, "message": message})
