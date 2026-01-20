-- docker/postgres/init.sql
-- ==============================================================================
-- CYBERGUARD DATABASE INITIALIZATION SCRIPT
-- ==============================================================================

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";  -- For UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- For cryptographic functions
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";  -- For query statistics

-- Create schema for better organization
CREATE SCHEMA IF NOT EXISTS cyberguard;
SET search_path TO cyberguard, public;

-- ==============================================================================
-- TABLES FOR SECURITY SCANS
-- ==============================================================================

-- Websites table - stores scanned websites
CREATE TABLE websites (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    url TEXT NOT NULL UNIQUE,
    domain TEXT GENERATED ALWAYS AS (regexp_replace(url, '^https?://([^/]+).*$', '\1')) STORED,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_scan_at TIMESTAMP WITH TIME ZONE,
    total_scans INTEGER DEFAULT 0,
    risk_score FLOAT DEFAULT 0.0,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Indexes for performance
    CONSTRAINT valid_url CHECK (url ~ '^https?://[^\s/$.?#].[^\s]*$')
);

-- Create indexes
CREATE INDEX idx_websites_domain ON websites(domain);
CREATE INDEX idx_websites_risk_score ON websites(risk_score DESC);
CREATE INDEX idx_websites_last_scan ON websites(last_scan_at DESC);

-- Scans table - individual scan results
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    scan_duration INTERVAL,
    risk_score FLOAT,
    confidence_score FLOAT,
    vulnerabilities_found INTEGER DEFAULT 0,
    critical_vulnerabilities INTEGER DEFAULT 0,
    scan_config JSONB,
    scan_results JSONB,  -- Full scan results
    error_message TEXT,
    
    -- Indexes
    INDEX idx_scans_website ON scans(website_id),
    INDEX idx_scans_status ON scans(status),
    INDEX idx_scans_completed ON scans(completed_at DESC),
    INDEX idx_scans_risk ON scans(risk_score DESC NULLS LAST)
);

-- ==============================================================================
-- TABLES FOR VULNERABILITIES
-- ==============================================================================

-- Vulnerability types (OWASP Top-10 and more)
CREATE TABLE vulnerability_types (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cwe_id VARCHAR(10),  -- Common Weakness Enumeration ID
    name VARCHAR(100) NOT NULL,
    description TEXT,
    category VARCHAR(50) CHECK (category IN ('injection', 'broken-auth', 'sensitive-data', 'xxe', 
                                           'broken-access', 'security-misconfig', 'xss', 'insecure-deserialization',
                                           'components', 'logging', 'api', 'other')),
    severity VARCHAR(10) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    remediation TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_vuln_types_severity ON vulnerability_types(severity),
    INDEX idx_vuln_types_category ON vulnerability_types(category)
);

-- Insert OWASP Top-10 vulnerability types
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

-- Vulnerabilities found in scans
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vulnerability_type_id UUID REFERENCES vulnerability_types(id),
    name VARCHAR(200) NOT NULL,
    description TEXT,
    location TEXT,  -- Where vulnerability was found (URL, parameter, etc.)
    evidence TEXT,  -- Proof of vulnerability
    severity VARCHAR(10) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    cvss_score FLOAT CHECK (cvss_score >= 0 AND cvss_score <= 10),
    confidence FLOAT CHECK (confidence >= 0 AND confidence <= 1),
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'confirmed', 'false-positive', 'remediated', 'risk-accepted')),
    remediation TEXT,
    remediation_status VARCHAR(20) DEFAULT 'pending' CHECK (remediation_status IN ('pending', 'in-progress', 'completed', 'not-applicable')),
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    remediated_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB,  -- Additional vulnerability metadata
    
    -- Indexes
    INDEX idx_vulnerabilities_scan ON vulnerabilities(scan_id),
    INDEX idx_vulnerabilities_severity ON vulnerabilities(severity),
    INDEX idx_vulnerabilities_status ON vulnerabilities(status),
    INDEX idx_vulnerabilities_cvss ON vulnerabilities(cvss_score DESC)
);

-- ==============================================================================
-- TABLES FOR AGENT SYSTEM
-- ==============================================================================

-- Security agents
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id VARCHAR(50) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    agent_type VARCHAR(50) CHECK (agent_type IN ('threat-detection', 'traffic-anomaly', 'bot-detection', 
                                               'malware', 'exploit-chain', 'forensics', 'incident-response',
                                               'compliance', 'code-review', 'threat-education')),
    version VARCHAR(20),
    status VARCHAR(20) DEFAULT 'inactive' CHECK (status IN ('active', 'inactive', 'error', 'maintenance')),
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    total_analyses BIGINT DEFAULT 0,
    success_rate FLOAT DEFAULT 0.0,
    avg_processing_time FLOAT,
    configuration JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_agents_type ON agents(agent_type),
    INDEX idx_agents_status ON agents(status)
);

-- Agent analyses
CREATE TABLE agent_analyses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agents(id),
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    findings JSONB,  -- Agent-specific findings
    confidence FLOAT,
    processing_time FLOAT,
    error_message TEXT,
    
    INDEX idx_agent_analyses_scan ON agent_analyses(scan_id),
    INDEX idx_agent_analyses_agent ON agent_analyses(agent_id),
    INDEX idx_agent_analyses_status ON agent_analyses(status)
);

-- ==============================================================================
-- TABLES FOR THREAT INTELLIGENCE
-- ==============================================================================

-- CVE database
CREATE TABLE cves (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cve_id VARCHAR(20) NOT NULL UNIQUE,
    description TEXT,
    cvss_score FLOAT,
    cvss_severity VARCHAR(10),
    published_date DATE,
    last_modified_date DATE,
    affected_products TEXT[],
    references JSONB,
    exploit_available BOOLEAN DEFAULT FALSE,
    exploited_in_wild BOOLEAN DEFAULT FALSE,
    metadata JSONB,
    
    INDEX idx_cves_cvss ON cves(cvss_score DESC),
    INDEX idx_cves_published ON cves(published_date DESC),
    INDEX idx_cves_exploit ON cves(exploit_available)
);

-- Threat indicators (IPs, domains, hashes)
CREATE TABLE threat_indicators (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    indicator_type VARCHAR(20) CHECK (indicator_type IN ('ip', 'domain', 'url', 'hash', 'email')),
    value TEXT NOT NULL,
    threat_type VARCHAR(50),
    severity VARCHAR(10),
    source VARCHAR(100),
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    confidence FLOAT,
    tags TEXT[],
    metadata JSONB,
    
    -- Ensure unique indicators
    UNIQUE(indicator_type, value),
    
    INDEX idx_threat_indicators_type ON threat_indicators(indicator_type),
    INDEX idx_threat_indicators_severity ON threat_indicators(severity),
    INDEX idx_threat_indicators_last_seen ON threat_indicators(last_seen DESC)
);

-- ==============================================================================
-- TABLES FOR INCIDENT RESPONSE
-- ==============================================================================

-- Security incidents
CREATE TABLE incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id VARCHAR(50) NOT NULL UNIQUE GENERATED ALWAYS AS ('INC-' || lpad((id::text), 8, '0')) STORED,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    severity VARCHAR(10) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'contained', 'resolved', 'closed')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE,
    assigned_to UUID,  -- User ID
    related_scan_id UUID REFERENCES scans(id),
    root_cause TEXT,
    impact_assessment TEXT,
    
    INDEX idx_incidents_severity ON incidents(severity),
    INDEX idx_incidents_status ON incidents(status),
    INDEX idx_incidents_created ON incidents(created_at DESC)
);

-- Incident timeline
CREATE TABLE incident_timeline (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(50) CHECK (event_type IN ('created', 'updated', 'comment', 'attachment', 'status-change', 
                                               'assignment', 'escalation', 'resolution')),
    description TEXT,
    created_by UUID,  -- User ID
    metadata JSONB,
    
    INDEX idx_incident_timeline_incident ON incident_timeline(incident_id),
    INDEX idx_incident_timeline_timestamp ON incident_timeline(timestamp DESC)
);

-- ==============================================================================
-- TABLES FOR AUDIT LOGGING
-- ==============================================================================

-- Audit logs
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    user_id UUID,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    ip_address INET,
    user_agent TEXT,
    request_method VARCHAR(10),
    request_path TEXT,
    status_code INTEGER,
    details JSONB,
    
    INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC),
    INDEX idx_audit_logs_user ON audit_logs(user_id),
    INDEX idx_audit_logs_action ON audit_logs(action)
);

-- ==============================================================================
-- TABLES FOR USER MANAGEMENT
-- ==============================================================================

-- Users
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('admin', 'security-analyst', 'developer', 'viewer')),
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP WITH TIME ZONE,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret TEXT,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_users_email ON users(email),
    INDEX idx_users_role ON users(role)
);

-- API keys
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    key_hash TEXT NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    permissions JSONB,  -- Array of permissions
    last_used TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_api_keys_user ON api_keys(user_id),
    INDEX idx_api_keys_expires ON api_keys(expires_at)
);

-- ==============================================================================
-- FUNCTIONS AND TRIGGERS
-- ==============================================================================

-- Update timestamp function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply update triggers to relevant tables
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

-- Function to calculate website risk score
CREATE OR REPLACE FUNCTION calculate_website_risk_score(website_uuid UUID)
RETURNS FLOAT AS $$
DECLARE
    max_cvss FLOAT;
    vuln_count INTEGER;
    recent_scans INTEGER;
BEGIN
    -- Get maximum CVSS score from recent vulnerabilities
    SELECT MAX(v.cvss_score), COUNT(*) INTO max_cvss, vuln_count
    FROM scans s
    JOIN vulnerabilities v ON s.id = v.scan_id
    WHERE s.website_id = website_uuid
    AND s.completed_at > CURRENT_TIMESTAMP - INTERVAL '30 days'
    AND v.status = 'open';
    
    -- Count recent scans
    SELECT COUNT(*) INTO recent_scans
    FROM scans
    WHERE website_id = website_uuid
    AND completed_at > CURRENT_TIMESTAMP - INTERVAL '30 days';
    
    -- Calculate risk score (0-1)
    RETURN COALESCE(
        (max_cvss * 0.1) +  -- CVSS contribution (max 1.0)
        (LEAST(vuln_count, 10) * 0.05) +  -- Vulnerability count contribution (max 0.5)
        (CASE WHEN recent_scans = 0 THEN 0.3 ELSE 0.0 END),  -- Penalty for no recent scans
        0.0
    );
END;
$$ LANGUAGE plpgsql;

-- Function to update website risk score
CREATE OR REPLACE FUNCTION update_website_risk_score()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE websites
    SET risk_score = calculate_website_risk_score(NEW.website_id),
        updated_at = CURRENT_TIMESTAMP,
        last_scan_at = NEW.completed_at,
        total_scans = total_scans + 1
    WHERE id = NEW.website_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to update website risk score after scan completion
CREATE TRIGGER update_risk_score_after_scan
AFTER UPDATE OF status ON scans
FOR EACH ROW
WHEN (NEW.status = 'completed' AND OLD.status != 'completed')
EXECUTE FUNCTION update_website_risk_score();

-- ==============================================================================
-- VIEWS FOR REPORTING
-- ==============================================================================

-- Dashboard summary view
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

-- Recent scans view
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

-- Top vulnerable websites view
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

-- ==============================================================================
-- PERMISSIONS AND ROLES
-- ==============================================================================

-- Create application user with limited permissions
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cyberguard_app') THEN
        CREATE USER cyberguard_app WITH PASSWORD '${DB_PASSWORD}';
    END IF;
END
$$;

-- Grant permissions
GRANT CONNECT ON DATABASE cyberguard_db TO cyberguard_app;
GRANT USAGE ON SCHEMA cyberguard TO cyberguard_app;

-- Grant table permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA cyberguard TO cyberguard_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA cyberguard TO cyberguard_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA cyberguard TO cyberguard_app;

-- Grant view permissions
GRANT SELECT ON ALL TABLES IN SCHEMA cyberguard TO cyberguard_app;

-- ==============================================================================
-- INITIAL DATA
-- ==============================================================================

-- Insert default admin user (password: Admin123! - change immediately)
INSERT INTO users (username, email, password_hash, full_name, role, is_active) VALUES
('admin', 'admin@cyberguard.ai', crypt('Admin123!', gen_salt('bf', 12)), 'System Administrator', 'admin', true);

-- Insert initial agents
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