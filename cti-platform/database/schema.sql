-- ============================================================================
-- Cyber Threat Intelligence (CTI) Platform - Database Schema
-- Database: MySQL 8.0+
-- ============================================================================

CREATE DATABASE IF NOT EXISTS cti_platform
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE cti_platform;

-- ----------------------------------------------------------------------------
-- Table: users
-- Stores platform users. Two roles are supported: 'admin' and 'analyst'.
-- Admins can manage users/settings; analysts manage IOCs/events/reports.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(50)  NOT NULL UNIQUE,
    email           VARCHAR(120) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    full_name       VARCHAR(120) DEFAULT NULL,
    role            ENUM('admin', 'analyst') NOT NULL DEFAULT 'analyst',
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_login      DATETIME DEFAULT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- Table: threat_events
-- Represents a threat event, mirroring MISP event structure so it can be
-- pushed to / pulled from MISP via PyMISP.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_events (
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    misp_event_id       VARCHAR(64) DEFAULT NULL,      -- ID/UUID of linked MISP event
    misp_uuid           VARCHAR(64) DEFAULT NULL,
    title               VARCHAR(255) NOT NULL,
    description         TEXT,
    threat_level        ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
    analysis_status     ENUM('initial','ongoing','completed') NOT NULL DEFAULT 'initial',
    distribution        VARCHAR(50) DEFAULT 'Your organisation only',
    org                 VARCHAR(120) DEFAULT NULL,
    event_date          DATE DEFAULT NULL,
    is_published        BOOLEAN NOT NULL DEFAULT FALSE,
    created_by          INT DEFAULT NULL,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                        ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_event_created_by FOREIGN KEY (created_by)
        REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_threat_level (threat_level),
    INDEX idx_misp_event_id (misp_event_id)
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- Table: ioc_attributes
-- Indicators of Compromise linked to a threat event.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ioc_attributes (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    event_id        INT DEFAULT NULL,
    ioc_type        ENUM('ip','domain','url','email','hash_md5','hash_sha1','hash_sha256') NOT NULL,
    ioc_value       VARCHAR(500) NOT NULL,
    category        VARCHAR(100) DEFAULT 'Network activity',
    severity        ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
    confidence_score INT DEFAULT 50,                    -- 0-100
    source          VARCHAR(100) DEFAULT 'manual',       -- manual, misp, virustotal, otx, abuseipdb
    tags            VARCHAR(500) DEFAULT NULL,
    is_correlated   BOOLEAN NOT NULL DEFAULT FALSE,
    correlation_count INT DEFAULT 0,
    first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen       DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by      INT DEFAULT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_ioc_event FOREIGN KEY (event_id)
        REFERENCES threat_events(id) ON DELETE CASCADE,
    CONSTRAINT fk_ioc_created_by FOREIGN KEY (created_by)
        REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_ioc_value (ioc_value(191)),
    INDEX idx_ioc_type (ioc_type),
    INDEX idx_severity (severity)
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- Table: reports
-- Generated PDF reports (event-level or full platform summary reports).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    title           VARCHAR(255) NOT NULL,
    report_type     ENUM('event','ioc','summary') NOT NULL DEFAULT 'summary',
    event_id        INT DEFAULT NULL,
    file_path       VARCHAR(500) NOT NULL,
    generated_by    INT DEFAULT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_report_event FOREIGN KEY (event_id)
        REFERENCES threat_events(id) ON DELETE SET NULL,
    CONSTRAINT fk_report_user FOREIGN KEY (generated_by)
        REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- Table: activity_logs
-- Audit trail of user actions across the platform.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS activity_logs (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT DEFAULT NULL,
    action          VARCHAR(100) NOT NULL,       -- e.g. LOGIN, CREATE_IOC, DELETE_EVENT
    description     VARCHAR(500) DEFAULT NULL,
    ip_address      VARCHAR(45) DEFAULT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_log_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_action (action),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- Table: api_configuration
-- Stores API keys / endpoints for MISP, VirusTotal, OTX, AbuseIPDB.
-- Keys should still be overridable via .env; DB copy lets admins update
-- them at runtime from the Settings page.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_configuration (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    service_name    VARCHAR(50) NOT NULL UNIQUE,   -- misp, virustotal, otx, abuseipdb
    base_url        VARCHAR(255) DEFAULT NULL,
    api_key         VARCHAR(500) DEFAULT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_checked    DATETIME DEFAULT NULL,
    status          ENUM('connected','disconnected','unknown') NOT NULL DEFAULT 'unknown',
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;
