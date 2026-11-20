# Live assessment prioritization with Gemini

The Analyst sends the existing organization-scoped assessment selection to the server.
Live Gemini is explicitly enabled at server startup. The existing organization,
AI use, and reporting permissions govern every request.

Only allowlisted Windows check categories, severity values, and request-local
references are sent to Gemini. The server validates the full returned ordering
and builds recommendations from its existing rules and stored assessment.
Unavailable or invalid inference falls back to those rules with a provider label.

Acceptance covers the opt-in, tenant isolation, payload minimization, returned
ordering and fallback. The local model continues to use the LM Studio listener.
