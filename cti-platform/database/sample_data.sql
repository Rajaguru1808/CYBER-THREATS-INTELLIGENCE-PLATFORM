-- ============================================================================
-- Sample data for the CTI Platform
-- Run AFTER schema.sql. Passwords below are bcrypt hashes for: Admin@123 / Analyst@123
-- (Generated using werkzeug.security.generate_password_hash - see app/utils/seed.py
--  if you want to regenerate hashes yourself)
-- ============================================================================

USE cti_platform;

-- Default users (password for both: see README "Default Credentials")
-- NOTE: hashes are placeholders here; the app's `flask seed-db` CLI command
-- (see run.py) generates real werkzeug hashes at seed time. This file is kept
-- for reference / manual MySQL import and is overwritten in effect by seed-db.
INSERT INTO users (username, email, password_hash, full_name, role, is_active) VALUES
('admin',   'admin@ctiplatform.local',   'placeholder_will_be_reset_by_seed_script', 'Platform Administrator', 'admin', TRUE),
('analyst', 'analyst@ctiplatform.local', 'placeholder_will_be_reset_by_seed_script', 'SOC Analyst', 'analyst', TRUE);

-- Sample threat events
INSERT INTO threat_events (title, description, threat_level, analysis_status, org, event_date, is_published, created_by) VALUES
('Emotet Banking Trojan Campaign', 'Resurgence of Emotet malspam campaign targeting financial institutions across APAC region.', 'critical', 'ongoing', 'CTI-Platform', '2026-07-01', TRUE, 1),
('Phishing Campaign Impersonating IT Helpdesk', 'Credential harvesting phishing emails impersonating internal IT helpdesk staff.', 'high', 'ongoing', 'CTI-Platform', '2026-07-05', TRUE, 2),
('Suspicious C2 Traffic - Cobalt Strike', 'Beaconing traffic patterns consistent with Cobalt Strike C2 framework detected.', 'critical', 'initial', 'CTI-Platform', '2026-07-08', FALSE, 1),
('Low Severity Port Scan Activity', 'Routine reconnaissance / port scanning activity from known scanner ranges.', 'low', 'completed', 'CTI-Platform', '2026-06-20', TRUE, 2),
('Ransomware IOC Bundle - LockBit', 'IOC bundle correlated with LockBit ransomware affiliate infrastructure.', 'critical', 'ongoing', 'CTI-Platform', '2026-07-10', TRUE, 1);

-- Sample IOC attributes
INSERT INTO ioc_attributes (event_id, ioc_type, ioc_value, category, severity, confidence_score, source, tags, is_correlated, correlation_count, created_by) VALUES
(1, 'ip', '185.220.101.45', 'Network activity', 'critical', 90, 'misp', 'emotet,c2', TRUE, 3, 1),
(1, 'domain', 'update-secure-bank.com', 'Network activity', 'high', 80, 'otx', 'emotet,phishing-domain', TRUE, 2, 1),
(1, 'hash_sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85', 'Payload delivery', 'critical', 95, 'virustotal', 'emotet,malware', FALSE, 0, 1),
(2, 'url', 'https://it-helpdesk-secure-login.net/reset', 'Payload delivery', 'high', 75, 'manual', 'phishing', FALSE, 0, 2),
(2, 'email', 'support@it-helpdesk-secure-login.net', 'Payload delivery', 'medium', 60, 'manual', 'phishing', FALSE, 0, 2),
(3, 'ip', '45.155.204.12', 'Network activity', 'critical', 85, 'abuseipdb', 'cobaltstrike,c2', TRUE, 4, 1),
(4, 'ip', '104.244.72.115', 'Network activity', 'low', 30, 'manual', 'scanner', FALSE, 0, 2),
(5, 'hash_sha1', 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3', 'Payload delivery', 'critical', 92, 'virustotal', 'lockbit,ransomware', TRUE, 5, 1),
(5, 'domain', 'lockbit-leaks-portal.onion.link', 'External analysis', 'critical', 88, 'otx', 'lockbit,leak-site', TRUE, 2, 1),
(NULL, 'ip', '8.8.8.8', 'Network activity', 'low', 10, 'manual', 'benign,reference', FALSE, 0, 2);

-- Sample API configuration entries (keys left blank - set via Settings page or .env)
INSERT INTO api_configuration (service_name, base_url, api_key, is_active, status) VALUES
('misp', 'https://localhost:8443', '', FALSE, 'unknown'),
('virustotal', 'https://www.virustotal.com/api/v3', '', FALSE, 'unknown'),
('otx', 'https://otx.alienvault.com/api/v1', '', FALSE, 'unknown'),
('abuseipdb', 'https://api.abuseipdb.com/api/v2', '', FALSE, 'unknown');

-- Sample activity logs
INSERT INTO activity_logs (user_id, action, description, ip_address) VALUES
(1, 'LOGIN', 'Admin logged in', '127.0.0.1'),
(1, 'CREATE_EVENT', 'Created event: Emotet Banking Trojan Campaign', '127.0.0.1'),
(2, 'LOGIN', 'Analyst logged in', '127.0.0.1'),
(2, 'CREATE_IOC', 'Added IOC: https://it-helpdesk-secure-login.net/reset', '127.0.0.1');
