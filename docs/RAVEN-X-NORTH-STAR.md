RAVEN-X NORTH STAR

RAVEN-X is evolving from a single-machine Windows security scanner into a privacy-first distributed endpoint security platform.

Primary reference deployment:

A college IT lab with approximately 70 Windows PCs.

Each PC runs a lightweight RAVEN-X agent.

A local RAVEN-X server manages the fleet over the LAN.

Core functionality must work without Internet connectivity.

Optional local LLM inference runs inside the private network.

Core endpoint/security data remains local by default.

The architecture must support:

- 1 endpoint
- 10 endpoints
- 100 endpoints
- future growth toward 1,000+ endpoints

without prematurely introducing unnecessary microservices or Kubernetes.

Core product areas:

- Authentication
- RBAC
- Organizations
- Endpoint identity
- Agent management
- Fleet management
- Endpoint groups
- Inventory
- Assessments
- Scheduling
- Findings
- Evidence
- Compliance
- Policy
- Remediation
- Reporting
- Audit
- Local AI
- Offline operation

Core principle:

RAVEN-X is not merely a scanner.

The scanner/assessment engine is one capability of a larger endpoint management platform.

The control plane and fleet experience are first-class product capabilities.

Security principle:

A registered endpoint is not automatically trusted.

AI is advisory.

AI must never independently authorize destructive actions.

Internet connectivity is optional for core operation.

The UI is a first-class product surface and must feel like a serious commercial security product.