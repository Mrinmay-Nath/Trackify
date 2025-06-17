-- ================================================
-- Bug Tracker MySQL Database Schema (Complete)
-- ================================================

-- Create database
CREATE DATABASE IF NOT EXISTS bug_tracker;
USE bug_tracker;

-- Users table
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    role ENUM('admin', 'developer', 'tester', 'user') DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Projects table
CREATE TABLE projects (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    status ENUM('active', 'inactive', 'archived') DEFAULT 'active',
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Project members table
CREATE TABLE project_members (
    id INT PRIMARY KEY AUTO_INCREMENT,
    project_id INT NOT NULL,
    user_id INT NOT NULL,
    role ENUM('owner', 'manager', 'developer', 'tester') DEFAULT 'developer',
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_project_member (project_id, user_id)
);

-- Bugs table
CREATE TABLE bugs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity ENUM('Critical', 'High', 'Medium', 'Low') NOT NULL,
    status ENUM('Open', 'In Progress', 'Testing', 'Resolved', 'Closed', 'Reopened') DEFAULT 'Open',
    priority ENUM('Urgent', 'High', 'Medium', 'Low') DEFAULT 'Medium',
    bug_type ENUM('Bug', 'Feature Request', 'Enhancement', 'Task') DEFAULT 'Bug',
    steps_to_reproduce TEXT,
    expected_behavior TEXT,
    actual_behavior TEXT,
    browser VARCHAR(50),
    os VARCHAR(50),
    device VARCHAR(50),
    version VARCHAR(50),
    environment ENUM('Production', 'Staging', 'Development', 'Testing') DEFAULT 'Production',
    assigned_to INT,
    created_by INT NOT NULL,
    project_id INT,
    duplicate_of INT,
    estimated_hours DECIMAL(5,2),
    actual_hours DECIMAL(5,2),
    due_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    closed_at TIMESTAMP NULL,
    FOREIGN KEY (assigned_to) REFERENCES users(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (project_id) REFERENCES projects(id),
    FOREIGN KEY (duplicate_of) REFERENCES bugs(id),
    INDEX idx_status (status),
    INDEX idx_severity (severity),
    INDEX idx_priority (priority),
    INDEX idx_assigned_to (assigned_to),
    INDEX idx_created_by (created_by),
    INDEX idx_project_id (project_id),
    INDEX idx_created_at (created_at),
    INDEX idx_due_date (due_date)
);

-- Bug tags table
CREATE TABLE bug_tags (
    id INT PRIMARY KEY AUTO_INCREMENT,
    bug_id INT NOT NULL,
    tag_name VARCHAR(50) NOT NULL,
    tag_type ENUM('ai_generated', 'manual') DEFAULT 'manual',
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bug_id) REFERENCES bugs(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id),
    UNIQUE KEY unique_bug_tag (bug_id, tag_name)
);

-- Predefined tags table
CREATE TABLE predefined_tags (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    color VARCHAR(7) DEFAULT '#007bff',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Bug comments/history table
CREATE TABLE bug_comments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    bug_id INT NOT NULL,
    user_id INT NOT NULL,
    comment TEXT NOT NULL,
    comment_type ENUM('comment', 'status_change', 'assignment', 'priority_change', 'severity_change') DEFAULT 'comment',
    old_value VARCHAR(100),
    new_value VARCHAR(100),
    is_internal BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (bug_id) REFERENCES bugs(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id),
    INDEX idx_bug_id (bug_id),
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at)
);

-- Bug attachments table
CREATE TABLE bug_attachments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    bug_id INT NOT NULL,
    filename VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    file_size INT,
    mime_type VARCHAR(100),
    description TEXT,
    uploaded_by INT NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bug_id) REFERENCES bugs(id) ON DELETE CASCADE,
    FOREIGN KEY (uploaded_by) REFERENCES users(id),
    INDEX idx_bug_id (bug_id)
);

-- Bug watchers table
CREATE TABLE bug_watchers (
    id INT PRIMARY KEY AUTO_INCREMENT,
    bug_id INT NOT NULL,
    user_id INT NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bug_id) REFERENCES bugs(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_bug_watcher (bug_id, user_id)
);

-- Bug relationships table
CREATE TABLE bug_relationships (
    id INT PRIMARY KEY AUTO_INCREMENT,
    bug_id INT NOT NULL,
    related_bug_id INT NOT NULL,
    relationship_type ENUM('blocks', 'blocked_by', 'duplicates', 'related_to', 'parent_of', 'child_of') NOT NULL,
    created_by INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bug_id) REFERENCES bugs(id) ON DELETE CASCADE,
    FOREIGN KEY (related_bug_id) REFERENCES bugs(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id),
    UNIQUE KEY unique_relationship (bug_id, related_bug_id, relationship_type)
);

-- Notifications table
CREATE TABLE notifications (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    bug_id INT,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    type ENUM('bug_assigned', 'bug_updated', 'bug_commented', 'bug_resolved', 'bug_closed', 'bug_reopened', 'bug_due_soon') NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    read_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (bug_id) REFERENCES bugs(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_is_read (is_read),
    INDEX idx_created_at (created_at)
);

-- Bug activity log table
CREATE TABLE bug_activity_log (
    id INT PRIMARY KEY AUTO_INCREMENT,
    bug_id INT NOT NULL,
    user_id INT NOT NULL,
    action ENUM('created', 'updated', 'commented', 'assigned', 'status_changed', 'priority_changed', 'severity_changed', 'closed', 'reopened') NOT NULL,
    field_name VARCHAR(50),
    old_value TEXT,
    new_value TEXT,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bug_id) REFERENCES bugs(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id),
    INDEX idx_bug_id (bug_id),
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at)
);

-- User preferences table
CREATE TABLE user_preferences (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    email_notifications BOOLEAN DEFAULT TRUE,
    push_notifications BOOLEAN DEFAULT TRUE,
    notification_frequency ENUM('immediate', 'daily', 'weekly') DEFAULT 'immediate',
    theme ENUM('light', 'dark', 'auto') DEFAULT 'light',
    items_per_page INT DEFAULT 25,
    default_project_id INT,
    timezone VARCHAR(50) DEFAULT 'UTC',
    language VARCHAR(10) DEFAULT 'en',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (default_project_id) REFERENCES projects(id),
    UNIQUE KEY unique_user_prefs (user_id)
);

-- API tokens table
CREATE TABLE api_tokens (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    token_name VARCHAR(100) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    permissions JSON,
    expires_at TIMESTAMP NULL,
    last_used_at TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token_hash (token_hash),
    INDEX idx_user_id (user_id)
);

-- ================================================
-- Insert Sample Data
-- ================================================

INSERT INTO users (username, email, password_hash, full_name, role) VALUES
('admin', 'admin@bugtracker.com', '$2b$10$hash_here', 'System Administrator', 'admin'),
('john_doe', 'john@example.com', '$2b$10$hash_here', 'John Doe', 'developer'),
('jane_smith', 'jane@example.com', '$2b$10$hash_here', 'Jane Smith', 'developer'),
('mike_jones', 'mike@example.com', '$2b$10$hash_here', 'Mike Jones', 'tester'),
('sarah_wilson', 'sarah@example.com', '$2b$10$hash_here', 'Sarah Wilson', 'developer'),
('alex_brown', 'alex@example.com', '$2b$10$hash_here', 'Alex Brown', 'developer');

INSERT INTO projects (name, description, created_by) VALUES
('Web Application', 'Main web application project', 1),
('Mobile App', 'Mobile application for iOS and Android', 1),
('API Service', 'Backend API service', 1),
('Dashboard', 'Admin dashboard application', 1);

INSERT INTO project_members (project_id, user_id, role) VALUES
(1, 1, 'owner'), (1, 2, 'developer'), (1, 3, 'developer'), (1, 4, 'tester'),
(2, 1, 'owner'), (2, 5, 'developer'), (2, 6, 'developer'),
(3, 1, 'owner'), (3, 2, 'developer'), (3, 3, 'developer'),
(4, 1, 'owner'), (4, 5, 'manager'), (4, 6, 'developer');

INSERT INTO predefined_tags (name, description, color) VALUES
('frontend', 'Frontend related issues', '#28a745'),
('backend', 'Backend related issues', '#dc3545'),
('database', 'Database related issues', '#ffc107'),
('ui/ux', 'User interface and experience issues', '#17a2b8'),
('performance', 'Performance related issues', '#fd7e14'),
('security', 'Security related issues', '#6f42c1'),
('mobile', 'Mobile specific issues', '#e83e8c'),
('api', 'API related issues', '#20c997');

INSERT INTO bugs (title, description, severity, status, priority, assigned_to, created_by, project_id, steps_to_reproduce, expected_behavior, actual_behavior, browser, os, environment) VALUES
('Login button not responsive on mobile', 'Users are unable to tap the login button in mobile view on iPhone 13. This only occurs in Safari browser.', 'Critical', 'Open', 'Urgent', 2, 1, 1, '1. Open Safari on iPhone 13\n2. Navigate to login page\n3. Try to tap login button\n4. Nothing happens', 'Login button should respond to touch', 'Login button does not respond to touch', 'Safari', 'iOS 16', 'Production'),
('Database connection timeout', 'Application throws timeout error when connecting to database during peak hours.', 'High', 'In Progress', 'High', 3, 1, 3, '1. Deploy application\n2. Wait for peak traffic hours\n3. Monitor connection logs', 'Stable database connection', 'Timeout errors occur', NULL, 'Linux', 'Production'),
('Email notifications not sending', 'Users report they are not receiving email notifications for password resets and account updates.', 'Medium', 'Resolved', 'Medium', 4, 1, 1, '1. Request password reset\n2. Check email inbox\n3. Wait 10 minutes\n4. Still no email received', 'Email should be received within 2 minutes', 'No email received after 10+ minutes', NULL, NULL, 'Production'),
('Page loading slowly', 'The dashboard page takes more than 10 seconds to load completely with all widgets.', 'Low', 'Closed', 'Low', 5, 1, 4, '1. Login to application\n2. Navigate to dashboard\n3. Time the loading process', 'Page should load within 3 seconds', 'Page takes 10+ seconds to load', 'Chrome', 'Windows 10', 'Production'),
('Form validation errors', 'Contact form allows submission without required fields being filled.', 'High', 'Open', 'High', 6, 1, 1, '1. Go to contact page\n2. Leave required fields empty\n3. Click submit\n4. Form submits without validation', 'Form should show validation errors', 'Form submits without validation', 'Firefox', 'macOS', 'Production');

INSERT INTO bug_tags (bug_id, tag_name, tag_type, created_by) VALUES
(1, 'frontend', 'manual', 1),
(1, 'mobile', 'manual', 1),
(1, 'ui/ux', 'manual', 1),
(2, 'backend', 'manual', 1),
(2, 'database', 'manual', 1),
(2, 'performance', 'manual', 1),
(3, 'backend', 'manual', 1),
(4, 'frontend', 'manual', 1),
(4, 'performance', 'manual', 1),
(5, 'frontend', 'manual', 1),
(5, 'validation', 'manual', 1);

INSERT INTO bug_comments (bug_id, user_id, comment, comment_type) VALUES
(1, 2, 'I can reproduce this issue. The touch events are not being registered properly on mobile Safari.', 'comment'),
(1, 1, 'Assigned to John for investigation', 'assignment'),
(2, 3, 'Added connection pooling to handle peak load better. Testing in staging environment.', 'comment'),
(3, 4, 'Fixed SMTP configuration. Email notifications are now working correctly.', 'comment'),
(3, 4, 'Moving to resolved status', 'status_change'),
(5, 6, 'Working on client-side validation implementation', 'comment');

INSERT INTO bug_watchers (bug_id, user_id) VALUES
(1, 1), (1, 2), (1, 4),
(2, 1), (2, 3),
(3, 1), (3, 4),
(4, 1), (4, 5),
(5, 1), (5, 6);

INSERT INTO user_preferences (user_id, email_notifications, theme, items_per_page, timezone) VALUES
(1, TRUE, 'dark', 50, 'UTC'),
(2, TRUE, 'light', 25, 'America/New_York'),
(3, TRUE, 'light', 25, 'Europe/London'),
(4, FALSE, 'dark', 10, 'UTC'),
(5, TRUE, 'auto', 25, 'America/Los_Angeles'),
(6, TRUE, 'light', 25, 'Australia/Sydney');

-- ================================================
-- Useful Views for Common Queries
-- ================================================

-- Bug summary view
CREATE VIEW bug_summary AS
SELECT 
    b.id,
    b.title,
    b.severity,
    b.status,
    b.priority,
    b.created_at,
    b.updated_at,
    p.name as project_name,
    creator.full_name as created_by_name,
    assignee.full_name as assigned_to_name,
    COUNT(DISTINCT bc.id) as comment_count,
    COUNT(DISTINCT ba.id) as attachment_count
FROM bugs b
LEFT JOIN projects p ON b.project_id = p.id
LEFT JOIN users creator ON b.created_by = creator.id
LEFT JOIN users assignee ON b.assigned_to = assignee.id
LEFT JOIN bug_comments bc ON b.id = bc.bug_id
LEFT JOIN bug_attachments ba ON b.id = ba.bug_id
GROUP BY b.id, b.title, b.severity, b.status, b.priority, b.created_at, b.updated_at, p.name, creator.full_name, assignee.full_name;

-- User activity view
CREATE VIEW user_activity AS
SELECT 
    u.id as user_id,
    u.full_name,
    COUNT(DISTINCT b.id) as bugs_created,
    COUNT(DISTINCT b2.id) as bugs_assigned,
    COUNT(DISTINCT bc.id) as comments_made,
    MAX(COALESCE(bc.created_at, b.created_at)) as last_activity
FROM users u
LEFT JOIN bugs b ON u.id = b.created_by
LEFT JOIN bugs b2 ON u.id = b2.assigned_to
LEFT JOIN bug_comments bc ON u.id = bc.user_id
GROUP BY u.id, u.full_name;

-- Project statistics view
CREATE VIEW project_stats AS
SELECT 
    p.id,
    p.name,
    COUNT(DISTINCT b.id) as total_bugs,
    COUNT(DISTINCT CASE WHEN b.status = 'Open' THEN b.id END) as open_bugs,
    COUNT(DISTINCT CASE WHEN b.status = 'In Progress' THEN b.id END) as in_progress_bugs,
    COUNT(DISTINCT CASE WHEN b.status = 'Resolved' THEN b.id END) as resolved_bugs,
    COUNT(DISTINCT CASE WHEN b.status = 'Closed' THEN b.id END) as closed_bugs,
    COUNT(DISTINCT CASE WHEN b.severity = 'Critical' THEN b.id END) as critical_bugs,
    COUNT(DISTINCT CASE WHEN b.severity = 'High' THEN b.id END) as high_bugs,
    COUNT(DISTINCT pm.user_id) as team_members
FROM projects p
LEFT JOIN bugs b ON p.id = b.project_id
LEFT JOIN project_members pm ON p.id = pm.project_id
GROUP BY p.id, p.name;