# Services package: encapsulates all external API integrations (MISP,
# VirusTotal, OTX, AbuseIPDB) and internal business logic (correlation,
# severity scoring, PDF report generation) — kept separate from controllers
# so routes stay thin and logic stays testable/reusable.
