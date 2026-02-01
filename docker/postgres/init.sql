-- docker/postgres/init.sql
-- CyberGuard Database Initialization Script

-- Create PostgreSQL extensions for additional functionality
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";  -- Enables generation of UUIDs (Universally Unique Identifiers)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- Provides cryptographic functions like password hashing
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";  -- Tracks execution statistics for SQL statements

-- Create a dedicated schema for CyberGuard tables to organize database objects
CREATE SCHEMA IF NOT EXISTS cyberguard;

-- Set the default search path so queries don't need schema prefix
SET search_path TO cyberguard, public;

-- ====================================================================
-- WEBSITES TABLE: Stores websites that will be security scanned
-- ====================================================================
CREATE TABLE websites (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),  -- Unique identifier using UUIDv4
    url TEXT NOT NULL UNIQUE,  -- Full website URL, must be unique
    domain TEXT GENERATED ALWAYS AS (regexp_replace(url, '^https?://([^/]+).*$', '\1')) STORED,  -- Automatically extract domain from URL
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- Record creation timestamp
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- Last update timestamp
    last_scan_at TIMESTAMP WITH TIME ZONE,  -- When this website was last scanned
    total_scans INTEGER DEFAULT 0,  -- Counter of total scans performed
    risk_score FLOAT DEFAULT 0.0,  -- Calculated risk score (0.0 to 1.0)
    is_active BOOLEAN DEFAULT TRUE,  -- Whether website is actively monitored
    
    -- Constraint to validate URL format using regular expression
    CONSTRAINT valid_url CHECK (url ~ '^https?://[^\s/$.?#].[^\s]*$')
);

-- Performance indexes for the websites table
CREATE INDEX idx_websites_domain ON websites(domain);
CREATE INDEX idx_websites_risk_score ON websites(risk_score DESC);
CREATE INDEX idx_websites_last_scan ON websites(last_scan_at DESC);

-- ====================================================================
-- SCANS TABLE: Records individual security scan executions
-- ====================================================================
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),  -- Unique scan identifier
    website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,  -- Foreign key to websites table with cascade delete
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- When scan started
    completed_at TIMESTAMP WITH TIME ZONE,  -- When scan finished
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),  -- Scan lifecycle state
    scan_duration INTERVAL,  -- How long the scan took (calculated)
    risk_score FLOAT,  -- Overall risk score for this scan
    confidence_score FLOAT,  -- How confident we are in scan results (0.0 to 1.0)
    vulnerabilities_found INTEGER DEFAULT 0,  -- Total vulnerabilities found
    critical_vulnerabilities INTEGER DEFAULT 0,  -- Count of critical severity vulnerabilities
    scan_config JSONB,  -- Configuration used for this scan (JSON format)
    scan_results JSONB,  -- Complete scan results in JSON format
    error_message TEXT,  -- Error details if scan failed
    
    -- Performance indexes
    INDEX idx_scans_website ON scans(website_id),
    INDEX idx_scans_status ON scans(status),
    INDEX idx_scans_completed ON scans(completed_at DESC),
    INDEX idx_scans_risk ON scans(risk_score DESC NULLS LAST)
);

-- ====================================================================
-- VULNERABILITY_TYPES TABLE: Catalog of known vulnerability patterns
-- ====================================================================
CREATE TABLE vulnerability_types (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),  -- Unique identifier
    cwe_id VARCHAR(10),  -- Common Weakness Enumeration identifier (e.g., "CWE-79")
    name VARCHAR(100) NOT NULL,  -- Human-readable vulnerability name
    description TEXT,  -- Detailed description
    category VARCHAR(50) CHECK (category IN ('injection', 'broken-auth', 'sensitive-data', 'xxe', 
                                           'broken-access', 'security-misconfig', 'xss', 'insecure-deserialization',
                                           'components', 'logging', 'api', 'other')),  -- OWASP categories
    severity VARCHAR(10) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),  -- Base severity
    remediation TEXT,  -- How to fix this vulnerability
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- When this type was added
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- Last update timestamp
    
    -- Indexes for filtering
    INDEX idx_vuln_types_severity ON vulnerability_types(severity),
    INDEX idx_vuln_types_category ON vulnerability_types(category)
);

-- Insert initial OWASP Top-10 vulnerability types
INSERT INTO vulnerability_types (cwe_id, name, description, category, severity) VALUES
('CWE-79', 'Cross-site Scripting (XSS)', 'Untrusted data in web application without proper validation or escaping', 'xss', 'high'),
('CWE-89', 'SQL Injection', 'Untrusted data in SQL queries without proper validation or parameterization', 'injection', 'critical'),
('CWE-352', 'Cross-Site Request Forgery (CSRF)', 'Allows attackers to perform actions on behalf of authenticated users', 'broken-auth', 'medium'),
('CWE-918', 'Server-Side Request Forgery (SSRF)', 'Allows attackers to make requests to internal resources', 'injection', 'high'),
('CWE-78', 'OS Command Injection', 'Allows execution of arbitrary operating system commands', 'injection', 'critical'),
('CWE-22', 'Path Traversal', 'Access to files and directories outside restricted directory', 'broken-access', 'high'),
('CWE-502', 'Deserialization of Untrusted Data', 'Deserialization of untrusted data leads to remote code execution', 'insecure-deserialization', 'critical'),
('CWE-434', 'Unrestricted File Upload', 'Allows upload of dangerous file types', 'broken-auth', 'high'),
('CWE-798', 'Use of Hard-coded Credentials', 'Embedded credentials in source code', 'sensitive-data', 'critical'),
('CWE-200', 'Information Exposure', 'Sensitive information exposure to unauthorized actors', 'sensitive-data', 'medium');

-- ====================================================================
-- VULNERABILITIES TABLE: Specific vulnerabilities found during scans
-- ====================================================================
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),  -- Unique vulnerability instance
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,  -- Which scan found this
    vulnerability_type_id UUID REFERENCES vulnerability_types(id),  -- Reference to vulnerability type catalog
    name VARCHAR(200) NOT NULL,  -- Specific name for this instance
    description TEXT,  -- Detailed description of this specific finding
    location TEXT,  -- Where found (URL, parameter, file path)
    evidence TEXT,  -- Proof or example of the vulnerability
    severity VARCHAR(10) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),  -- Actual severity
    cvss_score FLOAT CHECK (cvss_score >= 0 AND cvss_score <= 10),  -- CVSS score 0-10
    confidence FLOAT CHECK (confidence >= 0 AND confidence <= 1),  -- Confidence level 0-1
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'confirmed', 'false-positive', 'remediated', 'risk-accepted')),  -- Vulnerability lifecycle
    remediation TEXT,  -- Specific remediation steps
    remediation_status VARCHAR(20) DEFAULT 'pending' CHECK (remediation_status IN ('pending', 'in-progress', 'completed', 'not-applicable')),  -- Fix progress
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- When vulnerability was found
    remediated_at TIMESTAMP WITH TIME ZONE,  -- When vulnerability was fixed
    metadata JSONB,  -- Additional structured data about the vulnerability
    
    -- Performance indexes
    INDEX idx_vulnerabilities_scan ON vulnerabilities(scan_id),
    INDEX idx_vulnerabilities_severity ON vulnerabilities(severity),
    INDEX idx_vulnerabilities_status ON vulnerabilities(status),
    INDEX idx_vulnerabilities_cvss ON vulnerabilities(cvss_score DESC)
);

-- ====================================================================
-- AGENTS TABLE: Security analysis agents that perform scans
-- ====================================================================
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),  -- Internal agent identifier
    agent_id VARCHAR(50) NOT NULL UNIQUE,  -- External agent identifier
    name VARCHAR(100) NOT NULL,  -- Human-readable agent name
    agent_type VARCHAR(50) CHECK (agent_type IN ('threat-detection', 'traffic-anomaly', 'bot-detection', 
                                               'malware', 'exploit-chain', 'forensics', 'incident-response',
                                               'compliance', 'code-review', 'threat-education')),  -- Agent category
    version VARCHAR(20),  -- Agent software version
    status VARCHAR(20) DEFAULT 'inactive' CHECK (status IN ('active', 'inactive', 'error', 'maintenance')),  -- Agent status
    last_heartbeat TIMESTAMP WITH TIME ZONE,  -- Last communication from agent
    total_analyses BIGINT DEFAULT 0,  -- Total analyses performed
    success_rate FLOAT DEFAULT 0.0,  -- Percentage of successful analyses
    avg_processing_time FLOAT,  -- Average time per analysis
    configuration JSONB,  -- Agent configuration settings
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- When agent was registered
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- Last update timestamp
    
    -- Indexes for filtering
    INDEX idx_agents_type ON agents(agent_type),
    INDEX idx_agents_status ON agents(status)
);

-- ====================================================================
-- AGENT_ANALYSES TABLE: Records of individual agent analysis runs
-- ====================================================================
CREATE TABLE agent_analyses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),  -- Unique analysis identifier
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,  -- Associated scan
    agent_id UUID REFERENCES agents(id),  -- Which agent performed analysis
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- Analysis start time
    completed_at TIMESTAMP WITH TIME ZONE,  -- Analysis completion time
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),  -- Analysis status
    findings JSONB,  -- Raw findings from agent (JSON format)
    confidence FLOAT,  -- Agent's confidence in findings
    processing_time FLOAT,  -- How long analysis took (seconds)
    error_message TEXT,  -- Error if analysis failed
    
    -- Performance indexes
    INDEX idx_agent_analyses_scan ON agent_analyses(scan_id),
    INDEX idx_agent_analyses_agent ON agent_analyses(agent_id),
    INDEX idx_agent_analyses_status ON agent_analyses(status)
);

-- ====================================================================
-- CVES TABLE: Common Vulnerabilities and Exposures database
-- ====================================================================
CREATE TABLE cves (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),  -- Internal CVE identifier
    cve_id VARCHAR(20) NOT NULL UNIQUE,  -- Official CVE identifier (e.g., "CVE-2021-44228")
    description TEXT,  -- CVE description
    cvss_score FLOAT,  -- CVSS base score
    cvss_severity VARCHAR(10),  -- CVSS severity rating
    published_date DATE,  -- When CVE was published
    last_modified_date DATE,  -- Last modification date
    affected_products TEXT[],  -- Array of affected products
    references JSONB,  -- Reference URLs and resources
    exploit_available BOOLEAN DEFAULT FALSE,  -- Whether exploit code is available
    exploited_in_wild BOOLEAN DEFAULT FALSE,  -- Whether actively exploited
    metadata JSONB,  -- Additional CVE metadata
    
    -- Indexes for filtering
    INDEX idx_cves_cvss ON cves(cvss_score DESC),
    INDEX idx_cves_published ON cves(published_date DESC),
    INDEX idx_cves_exploit ON cves(exploit_available)
);

-- ====================================================================
-- THREAT_INDICATORS TABLE: Known malicious indicators (IoCs)
-- ====================================================================
CREATE TABLE threat_indicators (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),  -- Internal identifier
    indicator_type VARCHAR(20) CHECK (indicator_type IN ('ip', 'domain', 'url', 'hash', 'email')),  -- Type of indicator
    value TEXT NOT NULL,  -- Actual indicator value
    threat_type VARCHAR(50),  -- Type of threat (malware, phishing, etc.)
    severity VARCHAR(10),  -- Threat severity
    source VARCHAR(100),  -- Where this indicator came from
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- First observation
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- Most recent observation
    confidence FLOAT,  -- Confidence in indicator accuracy
    tags TEXT[],  -- Categorization tags
    metadata JSONB,  -- Additional indicator metadata
    
    -- Ensure unique combination of type and value
    UNIQUE(indicator_type, value),
    
    -- Performance indexes
    INDEX idx_threat_indicators_type ON threat_indicators(indicator_type),
    INDEX idx_threat_indicators_severity ON threat_indicators(severity),
    INDEX idx_threat_indicators_last_seen ON threat_indicators(last_seen DESC)
);

-- ====================================================================
-- INCIDENTS TABLE: Security incident tracking
-- ====================================================================
CREATE TABLE incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),  -- Internal incident identifier
    incident_id VARCHAR(50) NOT NULL UNIQUE GENERATED ALWAYS AS ('INC-' || lpad((id::text), 8, '0')) STORED,  -- Human-readable ID
    title VARCHAR(200) NOT NULL,  -- Incident title
    description TEXT,  -- Detailed description
    severity VARCHAR(10) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),  -- Incident severity
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'contained', 'resolved', 'closed')),  -- Incident status
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- When incident was created
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- Last update
    resolved_at TIMESTAMP WITH TIME ZONE,  -- When incident was resolved
    assigned_to UUID,  -- User assigned to investigate (references users.id)
    related_scan_id UUID REFERENCES scans(id),  -- Associated scan if applicable
    root_cause TEXT,  -- Determined root cause
    impact_assessment TEXT,  -- Business impact assessment
    
    -- Performance indexes
    INDEX idx_incidents_severity ON incidents(severity),
    INDEX idx_incidents_status ON incidents(status),
    INDEX idx_incidents_created ON incidents(created_at DESC)
);

-- ====================================================================
-- INCIDENT_TIMELINE TABLE: Timeline of events for each incident
-- ====================================================================
CREATE TABLE incident_timeline (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),  -- Timeline event identifier
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,  -- Parent incident
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- When event occurred
    event_type VARCHAR(50) CHECK (event_type IN ('created', 'updated', 'comment', 'attachment', 'status-change', 
                                               'assignment', 'escalation', 'resolution')),  -- Type of event
    description TEXT,  -- Event description
    created_by UUID,  -- User who created event (references users.id)
    metadata JSONB,  -- Additional event metadata
    
    -- Performance indexes
    INDEX idx_incident_timeline_incident ON incident_timeline(incident_id),
    INDEX idx_incident_timeline_timestamp ON incident_timeline(timestamp DESC)
);

-- ====================================================================
-- AUDIT_LOGS TABLE: System audit trail
-- ====================================================================
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),  -- Log entry identifier
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- When action occurred
    user_id UUID,  -- User who performed action (references users.id)
    action VARCHAR(100) NOT NULL,  -- Action performed
    resource_type VARCHAR(50),  -- Type of resource affected
    resource_id UUID,  -- Specific resource affected
    ip_address INET,  -- IP address of requester
    user_agent TEXT,  -- HTTP User-Agent header
    request_method VARCHAR(10),  -- HTTP method (GET, POST, etc.)
    request_path TEXT,  -- Request path
    status_code INTEGER,  -- HTTP status code
    details JSONB,  -- Additional action details
    
    -- Performance indexes
    INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC),
    INDEX idx_audit_logs_user ON audit_logs(user_id),
    INDEX idx_audit_logs_action ON audit_logs(action)
);

-- ====================================================================
-- USERS TABLE: System user accounts
-- ====================================================================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),  -- User identifier
    username VARCHAR(50) NOT NULL UNIQUE,  -- Login username
    email VARCHAR(255) NOT NULL UNIQUE,  -- User email address
    password_hash TEXT NOT NULL,  -- Hashed password (using pgcrypto)
    full_name VARCHAR(100),  -- User's full name
    role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('admin', 'security-analyst', 'developer', 'viewer')),  -- User role
    is_active BOOLEAN DEFAULT TRUE,  -- Whether account is active
    last_login TIMESTAMP WITH TIME ZONE,  -- Last successful login
    mfa_enabled BOOLEAN DEFAULT FALSE,  -- Multi-factor authentication status
    mfa_secret TEXT,  -- MFA secret key
    failed_login_attempts INTEGER DEFAULT 0,  -- Count of failed login attempts
    locked_until TIMESTAMP WITH TIME ZONE,  -- Account lock expiration
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- Account creation date
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- Last account update
    
    -- Performance indexes
    INDEX idx_users_email ON users(email),
    INDEX idx_users_role ON users(role)
);

-- ====================================================================
-- API_KEYS TABLE: API authentication keys
-- ====================================================================
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),  -- API key identifier
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,  -- Associated user
    key_hash TEXT NOT NULL UNIQUE,  -- Hashed API key value
    name VARCHAR(100) NOT NULL,  -- Descriptive name for the key
    permissions JSONB,  -- Permission set (JSON array)
    last_used TIMESTAMP WITH TIME ZONE,  -- Last time key was used
    expires_at TIMESTAMP WITH TIME ZONE,  -- Key expiration date
    is_active BOOLEAN DEFAULT TRUE,  -- Whether key is active
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- Creation timestamp
    
    -- Performance indexes
    INDEX idx_api_keys_user ON api_keys(user_id),
    INDEX idx_api_keys_expires ON api_keys(expires_at)
);

-- ====================================================================
-- DATABASE FUNCTIONS
-- ====================================================================

-- Function to automatically update 'updated_at' timestamp on row updates
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply update triggers to tables with updated_at columns
CREATE TRIGGER update_websites_updated_at BEFORE UPDATE ON websites
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_vulnerability_types_updated_at BEFORE UPDATE ON vulnerability_types
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_agents_updated_at BEFORE UPDATE ON agents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_incidents_updated_at BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to calculate website risk score based on recent vulnerabilities
CREATE OR REPLACE FUNCTION calculate_website_risk_score(website_uuid UUID)
RETURNS FLOAT AS $$
DECLARE
    max_cvss FLOAT;       -- Highest CVSS score from recent vulnerabilities
    vuln_count INTEGER;   -- Count of recent vulnerabilities
    recent_scans INTEGER; -- Count of scans in last 30 days
BEGIN
    -- Get maximum CVSS score and count of vulnerabilities from recent scans
    SELECT MAX(v.cvss_score), COUNT(*) INTO max_cvss, vuln_count
    FROM scans s
    JOIN vulnerabilities v ON s.id = v.scan_id
    WHERE s.website_id = website_uuid
    AND s.completed_at > CURRENT_TIMESTAMP - INTERVAL '30 days'
    AND v.status = 'open';
    
    -- Count how many scans were performed in last 30 days
    SELECT COUNT(*) INTO recent_scans
    FROM scans
    WHERE website_id = website_uuid
    AND completed_at > CURRENT_TIMESTAMP - INTERVAL '30 days';
    
    -- Calculate risk score (0.0 to 1.0)
    -- Formula: CVSS contribution (max 1.0) + vulnerability count contribution (max 0.5) + penalty for no recent scans
    RETURN COALESCE(
        (COALESCE(max_cvss, 0) * 0.1) +                    -- CVSS contribution (max 1.0)
        (LEAST(COALESCE(vuln_count, 0), 10) * 0.05) +      -- Vulnerability count contribution (max 0.5)
        (CASE WHEN COALESCE(recent_scans, 0) = 0 THEN 0.3 ELSE 0.0 END),  -- Penalty for no recent scans
        0.0
    );
END;
$$ LANGUAGE plpgsql;

-- Function to update website risk score after scan completion
CREATE OR REPLACE FUNCTION update_website_risk_score()
RETURNS TRIGGER AS $$
BEGIN
    -- Update website metrics when a scan completes
    UPDATE websites
    SET risk_score = calculate_website_risk_score(NEW.website_id),
        updated_at = CURRENT_TIMESTAMP,
        last_scan_at = NEW.completed_at,
        total_scans = total_scans + 1
    WHERE id = NEW.website_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to update website risk score automatically when scan status changes to 'completed'
CREATE TRIGGER update_risk_score_after_scan
AFTER UPDATE OF status ON scans
FOR EACH ROW
WHEN (NEW.status = 'completed' AND OLD.status != 'completed')
EXECUTE FUNCTION update_website_risk_score();

-- ====================================================================
-- DATABASE VIEWS FOR REPORTING
-- ====================================================================

-- Dashboard summary view for high-level metrics
CREATE VIEW dashboard_summary AS
SELECT 
    COUNT(DISTINCT w.id) as total_websites,
    COUNT(DISTINCT s.id) as total_scans,
    COUNT(DISTINCT CASE WHEN v.severity = 'critical' THEN v.id END) as critical_vulnerabilities,
    COUNT(DISTINCT CASE WHEN v.severity = 'high' THEN v.id END) as high_vulnerabilities,
    AVG(s.risk_score) as avg_risk_score,
    COUNT(DISTINCT CASE WHEN i.severity = 'critical' THEN i.id END) as open_critical_incidents
FROM websites w
LEFT JOIN scans s ON w.id = s.website_id
LEFT JOIN vulnerabilities v ON s.id = v.scan_id AND v.status = 'open'
LEFT JOIN incidents i ON i.status IN ('open', 'investigating');

-- View showing recent scans from the last 7 days
CREATE VIEW recent_scans AS
SELECT 
    s.id,
    w.url,
    s.started_at,
    s.completed_at,
    s.risk_score,
    s.vulnerabilities_found,
    s.critical_vulnerabilities,
    s.status
FROM scans s
JOIN websites w ON s.website_id = w.id
WHERE s.completed_at > CURRENT_TIMESTAMP - INTERVAL '7 days'
ORDER BY s.completed_at DESC;

-- View showing most vulnerable websites ordered by risk score
CREATE VIEW top_vulnerable_websites AS
SELECT 
    w.id,
    w.url,
    w.risk_score,
    COUNT(DISTINCT s.id) as scan_count,
    COUNT(DISTINCT v.id) as vulnerability_count,
    COUNT(DISTINCT CASE WHEN v.severity = 'critical' THEN v.id END) as critical_count,
    MAX(s.completed_at) as last_scan
FROM websites w
JOIN scans s ON w.id = s.website_id
LEFT JOIN vulnerabilities v ON s.id = v.scan_id AND v.status = 'open'
GROUP BY w.id, w.url, w.risk_score
ORDER BY w.risk_score DESC
LIMIT 50;

-- ====================================================================
-- DATABASE PERMISSIONS
-- ====================================================================

-- Create application user if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cyberguard_app') THEN
        CREATE USER cyberguard_app WITH PASSWORD '${DB_PASSWORD}';
    END IF;
END
$$;

-- Grant connect permission to the database
GRANT CONNECT ON DATABASE ${DB_NAME:-cyberguard_db} TO cyberguard_app;

-- Grant schema usage permission
GRANT USAGE ON SCHEMA cyberguard TO cyberguard_app;

-- Grant full CRUD permissions on all tables in the schema
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA cyberguard TO cyberguard_app;

-- Grant permission to use sequences (for auto-incrementing columns)
GRANT USAGE ON ALL SEQUENCES IN SCHEMA cyberguard TO cyberguard_app;

-- Grant execute permission on all functions
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA cyberguard TO cyberguard_app;

-- Grant select permission on all views
GRANT SELECT ON ALL TABLES IN SCHEMA cyberguard TO cyberguard_app;

-- ====================================================================
-- INITIAL DATA POPULATION
-- ====================================================================

-- Insert default admin user with encrypted password
-- Note: Password should be changed immediately after first login
INSERT INTO users (username, email, password_hash, full_name, role, is_active) VALUES
('admin', 'admin@cyberguard.ai', crypt('Admin123!', gen_salt('bf', 12)), 'System Administrator', 'admin', true);

-- Insert initial security agents
INSERT INTO agents (agent_id, name, agent_type, version, status) VALUES
('threat_detection_001', 'Web Threat Detection Agent', 'threat-detection', '1.0.0', 'active'),
('traffic_anomaly_001', 'Traffic Anomaly Agent', 'traffic-anomaly', '1.0.0', 'active'),
('bot_detection_001', 'Bot Detection Agent', 'bot-detection', '1.0.0', 'active'),
('malware_agent_001', 'Malware Payload Agent', 'malware', '1.0.0', 'active'),
('exploit_chain_001', 'Exploit Chain Reasoning Agent', 'exploit-chain', '1.0.0', 'active'),
('forensics_agent_001', 'Digital Forensics Agent', 'forensics', '1.0.0', 'active'),
('incident_response_001', 'Incident Response Agent', 'incident-response', '1.0.0', 'active'),
('compliance_agent_001', 'Compliance & Privacy Agent', 'compliance', '1.0.0', 'active'),
('code_review_001', 'Secure Code Review Agent', 'code-review', '1.0.0', 'active'),
('threat_education_001', 'Threat Education Agent', 'threat-education', '1.0.0', 'active');