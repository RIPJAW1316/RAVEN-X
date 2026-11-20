# Scanner picker and evidence report review

The shared assessment picker groups all existing scanner IDs by domain. A
domain toggle and each scanner button update the original selection payload.
Quick and full scans retain their existing IDs.

The reviewed report uses an authenticated POST and requires both reporting and
AI permissions. The server builds one scoped evidence snapshot per request,
uses the existing analyzer to prioritize it, and renders the same snapshot and
structured advisory in the preview or PDF. Local and opted-in Gemini inference
use their existing data boundaries. If inference cannot run, the report clearly
labels the fallback or missing evidence. JSON and CSV continue to export evidence.
