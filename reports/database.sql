-- ============================================
-- MOBILIS AUTHENTICATION DATABASE SETUP
-- PostgreSQL Database Schema
-- ============================================

-- ============================================
-- creating a api dbuser for mobilis_auth database

CREATE USER crm_api WITH ENCRYPTED PASSWORD 'mobilis123';
 GRANT CONNECT ON DATABASE mobilis_auth  TO crm_api;
 GRANT USAGE ON SCHEMA public TO crm_api; 
 GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO crm_api; 
 GRANT CONNECT ON DATABASE mobilis_auth TO crm_api;
 GRANT USAGE ON SCHEMA public TO crm_api;
 GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO crm_api;
 ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO crm_api;



-- Create Database
CREATE DATABASE mobilis_auth OWNER crm_api;

-- Connect to the database
\c mobilis_auth;

-- ============================================
-- 1. USERS TABLE (Core Authentication)
-- ============================================
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  phone_number VARCHAR(10) UNIQUE NOT NULL,
  role VARCHAR(50) NOT NULL DEFAULT 'commercial', -- 'commercial', 'admin', 'manager', etc
  first_name VARCHAR(100),
  last_name VARCHAR(100),
  email VARCHAR(100) UNIQUE,
  is_active BOOLEAN DEFAULT true,
  failed_login_attempts INT DEFAULT 0,
  locked_until TIMESTAMP NULL,
  last_login TIMESTAMP NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index on phone_number for faster queries
CREATE INDEX idx_users_phone ON users(phone_number);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_is_active ON users(is_active);

-- ============================================
-- 2. REFRESH TOKENS TABLE (Token Management)
-- ============================================
CREATE TABLE refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  is_revoked BOOLEAN DEFAULT false,
  revoked_at TIMESTAMP NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for token lookups
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_is_revoked ON refresh_tokens(is_revoked);

-- ============================================
-- 3. LOGIN HISTORY TABLE (Audit Trail)
-- ============================================
CREATE TABLE login_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  phone_number VARCHAR(10) NOT NULL,
  otp_requested_at TIMESTAMP,
  otp_verified_at TIMESTAMP,
  login_status VARCHAR(50), -- 'success', 'failed', 'locked', 'otp_expired'
  failure_reason VARCHAR(255),
  ip_address VARCHAR(45), -- Support IPv4 and IPv6
  device_info VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for audit queries
CREATE INDEX idx_login_history_user_id ON login_history(user_id);
CREATE INDEX idx_login_history_phone ON login_history(phone_number);
CREATE INDEX idx_login_history_created_at ON login_history(created_at);

-- ============================================
-- 4. OTP LOG TABLE (OTP Tracking)
-- ============================================
CREATE TABLE otp_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  phone_number VARCHAR(10) NOT NULL,
  otp_code VARCHAR(5) NOT NULL,
  request_count INT DEFAULT 1,
  max_requests INT DEFAULT 3,
  first_requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  is_verified BOOLEAN DEFAULT false,
  verification_attempts INT DEFAULT 0,
  max_attempts INT DEFAULT 3,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for OTP queries
CREATE INDEX idx_otp_logs_phone ON otp_logs(phone_number);
CREATE INDEX idx_otp_logs_expires_at ON otp_logs(expires_at);

-- ============================================
-- 5. MOBILIS PHONE PREFIXES TABLE
-- ============================================
CREATE TABLE mobilis_phone_prefixes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  prefix VARCHAR(3) NOT NULL UNIQUE, -- '06', '07', '05'
  provider_name VARCHAR(50) NOT NULL DEFAULT 'MOBILIS',
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index
CREATE INDEX idx_prefixes_prefix ON mobilis_phone_prefixes(prefix);

-- Insert Mobilis prefixes (adjust based on DSSI information)
INSERT INTO mobilis_phone_prefixes (prefix, provider_name, is_active) VALUES
  ('06', 'MOBILIS', true);

-- ============================================
-- 6. USER SESSIONS TABLE (Optional - for active sessions tracking)
-- ============================================
CREATE TABLE user_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  access_token_hash VARCHAR(255) NOT NULL,
  device_id VARCHAR(255),
  device_name VARCHAR(255),
  platform VARCHAR(50), -- 'iOS', 'Android', 'Web'
  app_version VARCHAR(20),
  is_active BOOLEAN DEFAULT true,
  last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL
);

-- Create indexes
CREATE INDEX idx_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_sessions_is_active ON user_sessions(is_active);
CREATE INDEX idx_sessions_expires_at ON user_sessions(expires_at);

-- ============================================
-- 7. AUDIT LOG TABLE (Security & Compliance)
-- ============================================
CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action VARCHAR(100) NOT NULL, -- 'LOGIN', 'LOGOUT', 'OTP_REQUEST', 'OTP_VERIFY', 'ACCOUNT_LOCKED'
  resource VARCHAR(100), -- What was acted upon
  details JSONB, -- Additional context
  ip_address VARCHAR(45),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);

-- ============================================
-- SAMPLE DATA - FOR TESTING ONLY
-- ============================================

-- Insert sample commercial users
INSERT INTO users (phone_number, role, first_name, last_name, email, is_active) VALUES
  ('0612345678', 'commercial', 'enzo', 'chaabnia', 'enzo.chaabnia@mobilis.com', true)

-- ============================================
-- VIEWS (Optional - for easier querying)
-- ============================================

-- Active users view
CREATE VIEW active_users_view AS
SELECT id, phone_number, first_name, last_name, email, role, last_login
FROM users
WHERE is_active = true;

-- Failed login attempts view
CREATE VIEW failed_login_attempts_view AS
SELECT 
  user_id,
  phone_number,
  COUNT(*) as attempt_count,
  MAX(created_at) as last_attempt
FROM login_history
WHERE login_status = 'failed'
GROUP BY user_id, phone_number
HAVING COUNT(*) > 0;

-- ============================================
-- END OF SCHEMA
-- ============================================


-- ============================================
-- MOBILIS AUTHENTICATION - ALL DATABASE FUNCTIONS
-- File: mobilis_functions.sql
-- Description: Complete set of functions for authentication system
-- ============================================

-- Connect to the mobilis_auth database

-- ============================================
-- 1. OTP MANAGEMENT FUNCTIONS
-- ============================================

-- Function: Generate OTP code (5 digits)
CREATE OR REPLACE FUNCTION generate_otp()
RETURNS VARCHAR(5) AS $$
BEGIN
  RETURN LPAD(FLOOR(RANDOM() * 100000)::TEXT, 5, '0');
END;
$$ LANGUAGE plpgsql;

-- Function: Check if OTP is valid (not expired, not exceeded attempts)
CREATE OR REPLACE FUNCTION is_otp_valid(p_phone_number VARCHAR(10))
RETURNS BOOLEAN AS $$
DECLARE
  v_otp RECORD;
BEGIN
  SELECT * INTO v_otp FROM otp_logs
  WHERE phone_number = p_phone_number
  ORDER BY created_at DESC
  LIMIT 1;
  
  -- Check if OTP exists
  IF v_otp IS NULL THEN
    RETURN FALSE;
  END IF;
  
  -- Check if expired
  IF v_otp.expires_at < NOW() THEN
    RETURN FALSE;
  END IF;
  
  -- Check if already verified
  IF v_otp.is_verified = TRUE THEN
    RETURN FALSE;
  END IF;
  
  -- Check if max attempts exceeded
  IF v_otp.verification_attempts >= v_otp.max_attempts THEN
    RETURN FALSE;
  END IF;
  
  RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Function: Verify OTP code
CREATE OR REPLACE FUNCTION verify_otp(
  p_phone_number VARCHAR(10),
  p_otp_code VARCHAR(5)
)
RETURNS TABLE(is_valid BOOLEAN, message VARCHAR(255)) AS $$
DECLARE
  v_otp RECORD;
  v_user_id UUID;
BEGIN
  -- Get latest OTP
  SELECT * INTO v_otp FROM otp_logs
  WHERE phone_number = p_phone_number
  ORDER BY created_at DESC
  LIMIT 1;
  
  -- Check if OTP exists
  IF v_otp IS NULL THEN
    RETURN QUERY SELECT FALSE, 'No OTP request found. Please request a new OTP.'::VARCHAR(255);
    RETURN;
  END IF;
  
  -- Check if expired
  IF v_otp.expires_at < NOW() THEN
    RETURN QUERY SELECT FALSE, 'OTP has expired. Please request a new one.'::VARCHAR(255);
    RETURN;
  END IF;
  
  -- Check if already verified
  IF v_otp.is_verified = TRUE THEN
    RETURN QUERY SELECT FALSE, 'OTP already used. Please request a new one.'::VARCHAR(255);
    RETURN;
  END IF;
  
  -- Check if max attempts exceeded
  IF v_otp.verification_attempts >= v_otp.max_attempts THEN
    -- Lock the account
    SELECT id INTO v_user_id FROM users WHERE phone_number = p_phone_number;
    IF v_user_id IS NOT NULL THEN
      UPDATE users 
      SET locked_until = NOW() + INTERVAL '1 hour'
      WHERE id = v_user_id;
    END IF;
    
    RETURN QUERY SELECT FALSE, 'Too many failed attempts. Account locked for 1 hour.'::VARCHAR(255);
    RETURN;
  END IF;
  
  -- Check if code matches
  IF v_otp.otp_code != p_otp_code THEN
    -- Increment failed attempts
    UPDATE otp_logs 
    SET verification_attempts = verification_attempts + 1
    WHERE id = v_otp.id;
    
    RETURN QUERY SELECT FALSE, CONCAT('Wrong OTP. ', (v_otp.max_attempts - v_otp.verification_attempts - 1), ' attempts remaining.')::VARCHAR(255);
    RETURN;
  END IF;
  
  -- OTP is correct!
  UPDATE otp_logs 
  SET is_verified = TRUE
  WHERE id = v_otp.id;
  
  RETURN QUERY SELECT TRUE, 'OTP verified successfully.'::VARCHAR(255);
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- 2. USER ACCOUNT MANAGEMENT FUNCTIONS
-- ============================================

-- Function: Reset failed login attempts
CREATE OR REPLACE FUNCTION reset_failed_login_attempts(p_user_id UUID)
RETURNS void AS $$
BEGIN
  UPDATE users
  SET failed_login_attempts = 0,
      locked_until = NULL,
      last_login = NOW(),
      updated_at = NOW()
  WHERE id = p_user_id;
END;
$$ LANGUAGE plpgsql;

-- Function: Increment failed login attempts and lock if needed
CREATE OR REPLACE FUNCTION increment_failed_login_attempts(p_user_id UUID)
RETURNS void AS $$
BEGIN
  UPDATE users
  SET failed_login_attempts = failed_login_attempts + 1,
      locked_until = CASE 
        WHEN (failed_login_attempts + 1) >= 3 THEN NOW() + INTERVAL '1 hour'
        ELSE locked_until
      END,
      updated_at = NOW()
  WHERE id = p_user_id;
END;
$$ LANGUAGE plpgsql;

-- Function: Lock user account
CREATE OR REPLACE FUNCTION lock_user_account(
  p_user_id UUID,
  p_duration_minutes INT DEFAULT 60
)
RETURNS void AS $$
BEGIN
  UPDATE users
  SET locked_until = NOW() + (p_duration_minutes || ' minutes')::INTERVAL,
      updated_at = NOW()
  WHERE id = p_user_id;
END;
$$ LANGUAGE plpgsql;

-- Function: Unlock user account
CREATE OR REPLACE FUNCTION unlock_user_account(p_user_id UUID)
RETURNS void AS $$
BEGIN
  UPDATE users
  SET locked_until = NULL,
      failed_login_attempts = 0,
      updated_at = NOW()
  WHERE id = p_user_id;
END;
$$ LANGUAGE plpgsql;

-- Function: Deactivate user account
CREATE OR REPLACE FUNCTION deactivate_user_account(p_user_id UUID)
RETURNS void AS $$
BEGIN
  UPDATE users
  SET is_active = FALSE,
      updated_at = NOW()
  WHERE id = p_user_id;
  
  -- Revoke all active sessions
  UPDATE user_sessions
  SET is_active = FALSE
  WHERE user_id = p_user_id;
  
  -- Revoke all refresh tokens
  UPDATE refresh_tokens
  SET is_revoked = TRUE,
      revoked_at = NOW()
  WHERE user_id = p_user_id;
END;
$$ LANGUAGE plpgsql;

-- Function: Check if user account is locked
CREATE OR REPLACE FUNCTION is_user_locked(p_user_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
  v_locked_until TIMESTAMP;
BEGIN
  SELECT locked_until INTO v_locked_until FROM users WHERE id = p_user_id;
  
  IF v_locked_until IS NULL THEN
    RETURN FALSE;
  END IF;
  
  IF v_locked_until > NOW() THEN
    RETURN TRUE;
  ELSE
    -- Auto-unlock
    UPDATE users SET locked_until = NULL WHERE id = p_user_id;
    RETURN FALSE;
  END IF;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- 3. LOGIN AUDIT FUNCTIONS
-- ============================================

-- Function: Log login attempt
CREATE OR REPLACE FUNCTION log_login_attempt(
  p_user_id UUID,
  p_phone_number VARCHAR(10),
  p_status VARCHAR(50),
  p_failure_reason VARCHAR(255) DEFAULT NULL,
  p_ip_address VARCHAR(45) DEFAULT NULL,
  p_device_info VARCHAR(255) DEFAULT NULL
)
RETURNS void AS $$
BEGIN
  INSERT INTO login_history (
    user_id,
    phone_number,
    login_status,
    failure_reason,
    ip_address,
    device_info,
    otp_requested_at,
    otp_verified_at
  )
  VALUES (
    p_user_id,
    p_phone_number,
    p_status,
    p_failure_reason,
    p_ip_address,
    p_device_info,
    CASE WHEN p_status IN ('success', 'otp_expired', 'locked') THEN NOW() END,
    CASE WHEN p_status = 'success' THEN NOW() END
  );
END;
$$ LANGUAGE plpgsql;

-- Function: Get failed login attempts in last N hours
CREATE OR REPLACE FUNCTION get_failed_login_attempts(
  p_phone_number VARCHAR(10),
  p_hours INT DEFAULT 24
)
RETURNS TABLE(attempt_count INT, first_attempt TIMESTAMP, last_attempt TIMESTAMP) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    COUNT(*)::INT,
    MIN(created_at),
    MAX(created_at)
  FROM login_history
  WHERE phone_number = p_phone_number
    AND login_status = 'failed'
    AND created_at > NOW() - (p_hours || ' hours')::INTERVAL;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- 4. SESSION MANAGEMENT FUNCTIONS
-- ============================================

-- Function: Create user session
CREATE OR REPLACE FUNCTION create_user_session(
  p_user_id UUID,
  p_access_token_hash VARCHAR(255),
  p_device_id VARCHAR(255),
  p_device_name VARCHAR(255),
  p_platform VARCHAR(50),
  p_app_version VARCHAR(20)
)
RETURNS UUID AS $$
DECLARE
  v_session_id UUID;
BEGIN
  v_session_id := gen_random_uuid();
  
  INSERT INTO user_sessions (
    id,
    user_id,
    access_token_hash,
    device_id,
    device_name,
    platform,
    app_version,
    expires_at
  )
  VALUES (
    v_session_id,
    p_user_id,
    p_access_token_hash,
    p_device_id,
    p_device_name,
    p_platform,
    p_app_version,
    NOW() + INTERVAL '7 days'
  );
  
  RETURN v_session_id;
END;
$$ LANGUAGE plpgsql;

-- Function: End user session
CREATE OR REPLACE FUNCTION end_user_session(p_session_id UUID)
RETURNS void AS $$
BEGIN
  UPDATE user_sessions
  SET is_active = FALSE
  WHERE id = p_session_id;
END;
$$ LANGUAGE plpgsql;

-- Function: Update session activity
CREATE OR REPLACE FUNCTION update_session_activity(p_session_id UUID)
RETURNS void AS $$
BEGIN
  UPDATE user_sessions
  SET last_activity = NOW()
  WHERE id = p_session_id;
END;
$$ LANGUAGE plpgsql;

-- Function: Get user active sessions count
CREATE OR REPLACE FUNCTION get_active_sessions_count(p_user_id UUID)
RETURNS INT AS $$
DECLARE
  v_count INT;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_sessions
  WHERE user_id = p_user_id AND is_active = TRUE AND expires_at > NOW();
  
  RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- 5. UTILITY FUNCTIONS
-- ============================================

-- Function: Check if phone number is valid Mobilis number
CREATE OR REPLACE FUNCTION is_valid_mobilis_phone(p_phone_number VARCHAR(10))
RETURNS BOOLEAN AS $$
DECLARE
  v_prefix VARCHAR(3);
  v_is_valid BOOLEAN;
BEGIN
  -- Extract prefix (first 2 characters)
  v_prefix := SUBSTRING(p_phone_number, 1, 2);
  
  -- Check if phone matches Algerian format (10 digits, starts with 0)
  IF p_phone_number !~ '^\d{10}$' THEN
    RETURN FALSE;
  END IF;
  
  -- Check if prefix exists in mobilis_phone_prefixes table
  SELECT EXISTS(
    SELECT 1 FROM mobilis_phone_prefixes
    WHERE prefix = v_prefix AND is_active = TRUE
  ) INTO v_is_valid;
  
  RETURN v_is_valid;
END;
$$ LANGUAGE plpgsql;

-- Function: Check if user exists by phone number
CREATE OR REPLACE FUNCTION user_exists_by_phone(p_phone_number VARCHAR(10))
RETURNS TABLE(user_id UUID, user_exists BOOLEAN) AS $$
DECLARE
  v_user_id UUID;
BEGIN
  SELECT id INTO v_user_id FROM users
  WHERE phone_number = p_phone_number AND is_active = TRUE
  LIMIT 1;
  
  IF v_user_id IS NULL THEN
    RETURN QUERY SELECT NULL::UUID, FALSE;
  ELSE
    RETURN QUERY SELECT v_user_id, TRUE;
  END IF;
END;
$$ LANGUAGE plpgsql;

-- Function: Get user by phone number
CREATE OR REPLACE FUNCTION get_user_by_phone(p_phone_number VARCHAR(10))
RETURNS TABLE(
  id UUID,
  phone_number VARCHAR(10),
  first_name VARCHAR(100),
  last_name VARCHAR(100),
  email VARCHAR(100),
  role VARCHAR(50),
  is_active BOOLEAN,
  is_locked BOOLEAN,
  locked_until TIMESTAMP
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    u.id,
    u.phone_number,
    u.first_name,
    u.last_name,
    u.email,
    u.role,
    u.is_active,
    CASE WHEN u.locked_until > NOW() THEN TRUE ELSE FALSE END,
    u.locked_until
  FROM users u
  WHERE u.phone_number = p_phone_number AND u.is_active = TRUE
  LIMIT 1;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- 6. STATISTICS & REPORTING FUNCTIONS
-- ============================================

-- Function: Get total active users
CREATE OR REPLACE FUNCTION get_total_active_users()
RETURNS INT AS $$
DECLARE
  v_count INT;
BEGIN
  SELECT COUNT(*) INTO v_count FROM users WHERE is_active = TRUE;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- Function: Get total locked users
CREATE OR REPLACE FUNCTION get_total_locked_users()
RETURNS INT AS $$
DECLARE
  v_count INT;
BEGIN
  SELECT COUNT(*) INTO v_count FROM users
  WHERE is_active = TRUE AND locked_until > NOW();
  RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- Function: Get login statistics for a date range
CREATE OR REPLACE FUNCTION get_login_statistics(
  p_start_date DATE,
  p_end_date DATE
)
RETURNS TABLE(
  login_date DATE,
  successful_logins INT,
  failed_logins INT,
  total_attempts INT,
  success_rate NUMERIC
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    DATE(lh.created_at),
    COUNT(CASE WHEN lh.login_status = 'success' THEN 1 END)::INT,
    COUNT(CASE WHEN lh.login_status = 'failed' THEN 1 END)::INT,
    COUNT(*)::INT,
    ROUND(
      (COUNT(CASE WHEN lh.login_status = 'success' THEN 1 END)::NUMERIC / 
       NULLIF(COUNT(*), 0)) * 100,
      2
    )
  FROM login_history lh
  WHERE DATE(lh.created_at) >= p_start_date
    AND DATE(lh.created_at) <= p_end_date
  GROUP BY DATE(lh.created_at)
  ORDER BY DATE(lh.created_at) DESC;
END;
$$ LANGUAGE plpgsql;

-- Function: Get most active users
CREATE OR REPLACE FUNCTION get_most_active_users(p_limit INT DEFAULT 10)
RETURNS TABLE(
  phone_number VARCHAR(10),
  first_name VARCHAR(100),
  last_name VARCHAR(100),
  login_count INT,
  last_login TIMESTAMP
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    u.phone_number,
    u.first_name,
    u.last_name,
    COUNT(lh.id)::INT,
    u.last_login
  FROM users u
  LEFT JOIN login_history lh ON u.id = lh.user_id
  WHERE u.is_active = TRUE AND lh.login_status = 'success'
  GROUP BY u.id, u.phone_number, u.first_name, u.last_name, u.last_login
  ORDER BY COUNT(lh.id) DESC
  LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- 7. CLEANUP & MAINTENANCE FUNCTIONS
-- ============================================

-- Function: Delete expired OTP logs
CREATE OR REPLACE FUNCTION cleanup_expired_otps()
RETURNS TABLE(deleted_count INT) AS $$
DECLARE
  v_deleted INT;
BEGIN
  DELETE FROM otp_logs WHERE expires_at < NOW();
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  
  RETURN QUERY SELECT v_deleted::INT;
END;
$$ LANGUAGE plpgsql;

-- Function: Delete expired refresh tokens
CREATE OR REPLACE FUNCTION cleanup_expired_refresh_tokens()
RETURNS TABLE(deleted_count INT) AS $$
DECLARE
  v_deleted INT;
BEGIN
  DELETE FROM refresh_tokens WHERE expires_at < NOW();
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  
  RETURN QUERY SELECT v_deleted::INT;
END;
$$ LANGUAGE plpgsql;

-- Function: Delete expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS TABLE(deleted_count INT) AS $$
DECLARE
  v_deleted INT;
BEGIN
  DELETE FROM user_sessions WHERE expires_at < NOW();
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  
  RETURN QUERY SELECT v_deleted::INT;
END;
$$ LANGUAGE plpgsql;

-- Function: Delete old audit logs (older than N days)
CREATE OR REPLACE FUNCTION cleanup_old_audit_logs(p_days INT DEFAULT 90)
RETURNS TABLE(deleted_count INT) AS $$
DECLARE
  v_deleted INT;
BEGIN
  DELETE FROM audit_logs
  WHERE created_at < NOW() - (p_days || ' days')::INTERVAL;
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  
  RETURN QUERY SELECT v_deleted::INT;
END;
$$ LANGUAGE plpgsql;

-- Function: Delete old login history (older than N days)
CREATE OR REPLACE FUNCTION cleanup_old_login_history(p_days INT DEFAULT 180)
RETURNS TABLE(deleted_count INT) AS $$
DECLARE
  v_deleted INT;
BEGIN
  DELETE FROM login_history
  WHERE created_at < NOW() - (p_days || ' days')::INTERVAL;
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  
  RETURN QUERY SELECT v_deleted::INT;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- 8. ADVANCED SECURITY FUNCTIONS
-- ============================================

-- Function: Detect suspicious activity
CREATE OR REPLACE FUNCTION detect_suspicious_activity()
RETURNS TABLE(
  phone_number VARCHAR(10),
  user_id UUID,
  failed_attempts INT,
  last_attempt TIMESTAMP,
  risk_level VARCHAR(50)
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    lh.phone_number,
    lh.user_id,
    COUNT(CASE WHEN lh.login_status = 'failed' THEN 1 END)::INT,
    MAX(lh.created_at),
    CASE 
      WHEN COUNT(CASE WHEN lh.login_status = 'failed' THEN 1 END) >= 5 THEN 'CRITICAL'
      WHEN COUNT(CASE WHEN lh.login_status = 'failed' THEN 1 END) >= 3 THEN 'HIGH'
      WHEN COUNT(CASE WHEN lh.login_status = 'failed' THEN 1 END) >= 1 THEN 'MEDIUM'
      ELSE 'LOW'
    END
  FROM login_history lh
  WHERE lh.created_at > NOW() - INTERVAL '24 hours'
    AND lh.login_status = 'failed'
  GROUP BY lh.phone_number, lh.user_id
  HAVING COUNT(CASE WHEN lh.login_status = 'failed' THEN 1 END) > 0
  ORDER BY COUNT(CASE WHEN lh.login_status = 'failed' THEN 1 END) DESC;
END;
$$ LANGUAGE plpgsql;

-- Function: Create audit log entry
CREATE OR REPLACE FUNCTION create_audit_log(
  p_user_id UUID,
  p_action VARCHAR(100),
  p_resource VARCHAR(100),
  p_details JSONB DEFAULT NULL,
  p_ip_address VARCHAR(45) DEFAULT NULL
)
RETURNS void AS $$
BEGIN
  INSERT INTO audit_logs (user_id, action, resource, details, ip_address)
  VALUES (p_user_id, p_action, p_resource, p_details, p_ip_address);
END;
$$ LANGUAGE plpgsql;

-- Function: Get user activity summary
CREATE OR REPLACE FUNCTION get_user_activity_summary(p_user_id UUID)
RETURNS TABLE(
  total_logins INT,
  successful_logins INT,
  failed_logins INT,
  last_login TIMESTAMP,
  account_locked BOOLEAN,
  total_sessions INT,
  active_sessions INT
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    COUNT(lh.id)::INT,
    COUNT(CASE WHEN lh.login_status = 'success' THEN 1 END)::INT,
    COUNT(CASE WHEN lh.login_status = 'failed' THEN 1 END)::INT,
    (SELECT last_login FROM users WHERE id = p_user_id),
    (SELECT is_user_locked(p_user_id)),
    (SELECT COUNT(*) FROM user_sessions WHERE user_id = p_user_id)::INT,
    (SELECT COUNT(*) FROM user_sessions WHERE user_id = p_user_id AND is_active = TRUE AND expires_at > NOW())::INT
  FROM login_history lh
  WHERE lh.user_id = p_user_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- END OF FUNCTIONS FILE
-- ============================================
-- Total Functions: 29
-- Categories: OTP Management, User Account, Login Audit, Session, Utility, 
--             Statistics, Cleanup, Security
-- ============================================






