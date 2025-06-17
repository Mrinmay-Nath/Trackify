// ================================================
// Bug Tracker Backend API - Complete Implementation
// ================================================

// Dependencies
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult, param, query } = require('express-validator');
require('dotenv').config();
const aiTagsRoute = require('./routes/aiTags'); // ✅ AI tagging route
const cron = require('node-cron');
const nodemailer = require('nodemailer');
const { sendEmailNotification, checkDueBugs } = require('./services/notificationService');
// ================================================
// Express App Initialization

const app = express();
const PORT = process.env.PORT || 3000;

// ================================================
// Middleware Configuration
// ================================================

app.use(helmet());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = 'uploads/attachments/';
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt|zip/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Invalid file type'));
        }
    }
});

// ================================================
// Database Configuration
// ================================================

// Update database configuration
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'Denger@123',
    database: process.env.DB_NAME || 'bug_tracker',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

let pool;

// Initialize database connection
async function initializeDatabase() {
    try {
        // Create initial connection
        const connection = await mysql.createConnection({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD
        });

        // Create database if not exists
        await connection.query(`CREATE DATABASE IF NOT EXISTS ${process.env.DB_NAME}`);
        await connection.query(`USE ${process.env.DB_NAME}`);

        // Create users table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                full_name VARCHAR(100) NOT NULL,
                role ENUM('admin', 'developer', 'user') DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL,
                INDEX idx_username (username),
                INDEX idx_email (email)
            )
        `);

        // Close initial connection
        await connection.end();

        // Create the pool
        pool = mysql.createPool(dbConfig);

        // Test pool connection
        const [result] = await pool.execute('SELECT 1');
        console.log('Database and tables initialized successfully');
    } catch (error) {
        console.error('Database initialization failed:', error);
        process.exit(1);
    }
}

// ================================================
// Authentication Middleware
// ================================================

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

const requireRole = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
};

// ================================================
// Validation Middleware
// ================================================

const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            error: 'Validation failed', 
            details: errors.array() 
        });
    }
    next();
};

// ================================================
// Authentication Routes
// ================================================

// Register new user
app.post('/api/auth/register', [
    body('username').isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
    body('email').isEmail().withMessage('Valid email required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('full_name').notEmpty().withMessage('Full name is required')
], handleValidationErrors, async (req, res) => {
    try {
        const { username, email, password, full_name, role = 'user' } = req.body;
        
        // Check if user already exists
        const [existingUsers] = await pool.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );
        
        if (existingUsers.length > 0) {
            return res.status(409).json({ error: 'Username or email already exists' });
        }
        
        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Insert new user
        const [result] = await pool.execute(
            'INSERT INTO users (username, email, password_hash, full_name, role) VALUES (?, ?, ?, ?, ?)',
            [username, email, hashedPassword, full_name, role]
        );

        // Generate token for auto-login
        const token = jwt.sign(
            { 
                id: result.insertId,
                username,
                role
            },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '24h' }
        );
        
        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
                id: result.insertId,
                username,
                email,
                full_name,
                role
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Login user
app.post('/api/auth/login', [
    body('username').notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required')
], handleValidationErrors, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Find user
        const [users] = await pool.execute(
            'SELECT * FROM users WHERE username = ? OR email = ?',
            [username, username]
        );
        
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const user = users[0];
        
        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Update last login
        await pool.execute(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
            [user.id]
        );
        
        // Generate JWT token
        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username, 
                role: user.role 
            },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '24h' }
        );
        
        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                full_name: user.full_name,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get current user profile
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const [users] = await pool.execute(
            'SELECT id, username, email, full_name, role, created_at, last_login FROM users WHERE id = ?',
            [req.user.id]
        );
        
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json(users[0]);
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ================================================
// Bug Routes
// ================================================

// Get all bugs with filtering and pagination
app.get('/api/bugs', authenticateToken, [
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('status').optional().isIn(['Open', 'In Progress', 'Testing', 'Resolved', 'Closed', 'Reopened']),
    query('severity').optional().isIn(['Critical', 'High', 'Medium', 'Low']),
    query('priority').optional().isIn(['Urgent', 'High', 'Medium', 'Low'])
], handleValidationErrors, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 25;
        const offset = (page - 1) * limit;
        
        let whereClause = '1=1';
        const params = [];
        
        // Add filters
        if (req.query.status) {
            whereClause += ' AND b.status = ?';
            params.push(req.query.status);
        }
        if (req.query.severity) {
            whereClause += ' AND b.severity = ?';
            params.push(req.query.severity);
        }
        if (req.query.priority) {
            whereClause += ' AND b.priority = ?';
            params.push(req.query.priority);
        }
        if (req.query.project_id) {
            whereClause += ' AND b.project_id = ?';
            params.push(req.query.project_id);
        }
        if (req.query.assigned_to) {
            whereClause += ' AND b.assigned_to = ?';
            params.push(req.query.assigned_to);
        }
        if (req.query.search) {
            whereClause += ' AND (b.title LIKE ? OR b.description LIKE ?)';
            params.push(`%${req.query.search}%`, `%${req.query.search}%`);
        }
        
        // Get total count
        const [countResult] = await pool.execute(
            `SELECT COUNT(*) as total FROM bugs b WHERE ${whereClause}`,
            params
        );
        
        // Get bugs with pagination
        const query = `
            SELECT 
                b.*,
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
            WHERE ${whereClause}
            GROUP BY b.id
            ORDER BY b.created_at DESC
            LIMIT ? OFFSET ?
        `;
        
        const [bugs] = await pool.execute(query, [...params, limit, offset]);
        
        res.json({
            bugs,
            pagination: {
                page,
                limit,
                total: countResult[0].total,
                totalPages: Math.ceil(countResult[0].total / limit)
            }
        });
    } catch (error) {
        console.error('Get bugs error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get single bug by ID
app.get('/api/bugs/:id', authenticateToken, [
    param('id').isInt().withMessage('Bug ID must be an integer')
], handleValidationErrors, async (req, res) => {
    try {
        const bugId = req.params.id;
        
        // Get bug details
        const [bugs] = await pool.execute(`
            SELECT 
                b.*,
                p.name as project_name,
                creator.full_name as created_by_name,
                creator.username as created_by_username,
                assignee.full_name as assigned_to_name,
                assignee.username as assigned_to_username
            FROM bugs b
            LEFT JOIN projects p ON b.project_id = p.id
            LEFT JOIN users creator ON b.created_by = creator.id
            LEFT JOIN users assignee ON b.assigned_to = assignee.id
            WHERE b.id = ?
        `, [bugId]);
        
        if (bugs.length === 0) {
            return res.status(404).json({ error: 'Bug not found' });
        }
        
        const bug = bugs[0];
        
        // Get tags
        const [tags] = await pool.execute(`
            SELECT bt.tag_name, bt.tag_type, u.full_name as created_by_name
            FROM bug_tags bt
            LEFT JOIN users u ON bt.created_by = u.id
            WHERE bt.bug_id = ?
        `, [bugId]);
        
        // Get comments
        const [comments] = await pool.execute(`
            SELECT 
                bc.*,
                u.full_name,
                u.username
            FROM bug_comments bc
            JOIN users u ON bc.user_id = u.id
            WHERE bc.bug_id = ?
            ORDER BY bc.created_at ASC
        `, [bugId]);
        
        // Get attachments
        const [attachments] = await pool.execute(`
            SELECT 
                ba.*,
                u.full_name as uploaded_by_name
            FROM bug_attachments ba
            JOIN users u ON ba.uploaded_by = u.id
            WHERE ba.bug_id = ?
        `, [bugId]);
        
        // Get watchers
        const [watchers] = await pool.execute(`
            SELECT 
                bw.user_id,
                u.full_name,
                u.username
            FROM bug_watchers bw
            JOIN users u ON bw.user_id = u.id
            WHERE bw.bug_id = ?
        `, [bugId]);
        
        bug.tags = tags;
        bug.comments = comments;
        bug.attachments = attachments;
        bug.watchers = watchers;
        
        res.json(bug);
    } catch (error) {
        console.error('Get bug error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Create new bug
app.post('/api/bugs', authenticateToken, [
    body('title').notEmpty().withMessage('Title is required'),
    body('description').notEmpty().withMessage('Description is required'),
    body('severity').isIn(['Critical', 'High', 'Medium', 'Low']).withMessage('Invalid severity'),
    body('priority').optional().isIn(['Urgent', 'High', 'Medium', 'Low']).withMessage('Invalid priority'),
    body('project_id').optional().isInt().withMessage('Project ID must be an integer')
], handleValidationErrors, async (req, res) => {
    try {
        const {
            title, description, severity, priority = 'Medium', steps_to_reproduce,
            expected_behavior, actual_behavior, browser, os, device, version,
            environment = 'Production', project_id, assigned_to, tags = []
        } = req.body;
        
        // Insert bug
        const [result] = await pool.execute(`
            INSERT INTO bugs (
                title, description, severity, priority, steps_to_reproduce,
                expected_behavior, actual_behavior, browser, os, device, version,
                environment, project_id, assigned_to, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            title, description, severity, priority, steps_to_reproduce,
            expected_behavior, actual_behavior, browser, os, device, version,
            environment, project_id, assigned_to, req.user.id
        ]);
        
        const bugId = result.insertId;
        
        // Add tags if provided
        if (tags.length > 0) {
            const tagValues = tags.map(tag => [bugId, tag, 'manual', req.user.id]);
            await pool.execute(`
                INSERT INTO bug_tags (bug_id, tag_name, tag_type, created_by) VALUES ?
            `, [tagValues]);
        }
        
        // Add creator as watcher
        await pool.execute(
            'INSERT INTO bug_watchers (bug_id, user_id) VALUES (?, ?)',
            [bugId, req.user.id]
        );
        
        // Add assignee as watcher if different from creator
        if (assigned_to && assigned_to !== req.user.id) {
            await pool.execute(
                'INSERT INTO bug_watchers (bug_id, user_id) VALUES (?, ?)',
                [bugId, assigned_to]
            );
        }
        
        // Log activity
        await pool.execute(`
            INSERT INTO bug_activity_log (bug_id, user_id, action, description)
            VALUES (?, ?, 'created', 'Bug created')
        `, [bugId, req.user.id]);
        
        // Create notifications for assigned user
        if (assigned_to && assigned_to !== req.user.id) {
            await pool.execute(`
                INSERT INTO notifications (user_id, bug_id, title, message, type)
                VALUES (?, ?, ?, ?, 'bug_assigned')
            `, [
                assigned_to, bugId,
                `Bug assigned: ${title}`,
                `You have been assigned a new bug: ${title}`
            ]);
        }
        
        res.status(201).json({
            message: 'Bug created successfully',
            bugId: bugId
        });
    } catch (error) {
        console.error('Create bug error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update bug
app.put('/api/bugs/:id', authenticateToken, [
    param('id').isInt().withMessage('Bug ID must be an integer'),
    body('title').optional().notEmpty().withMessage('Title cannot be empty'),
    body('description').optional().notEmpty().withMessage('Description cannot be empty'),
    body('severity').optional().isIn(['Critical', 'High', 'Medium', 'Low']),
    body('status').optional().isIn(['Open', 'In Progress', 'Testing', 'Resolved', 'Closed', 'Reopened']),
    body('priority').optional().isIn(['Urgent', 'High', 'Medium', 'Low'])
], handleValidationErrors, async (req, res) => {
    try {
        const bugId = req.params.id;
        
        // Check if bug exists and get current values
        const [currentBug] = await pool.execute(
            'SELECT * FROM bugs WHERE id = ?',
            [bugId]
        );
        
        if (currentBug.length === 0) {
            return res.status(404).json({ error: 'Bug not found' });
        }
        
        const current = currentBug[0];
        const updates = [];
        const values = [];
        const activities = [];
        
        // Build dynamic update query
        Object.keys(req.body).forEach(key => {
            if (req.body[key] !== undefined && current[key] !== req.body[key]) {
                updates.push(`${key} = ?`);
                values.push(req.body[key]);
                
                // Log activity for important changes
                if (['status', 'severity', 'priority', 'assigned_to'].includes(key)) {
                    activities.push({
                        action: key === 'assigned_to' ? 'assigned' : `${key}_changed`,
                        field_name: key,
                        old_value: current[key],
                        new_value: req.body[key]
                    });
                }
            }
        });
        
        if (updates.length === 0) {
            return res.status(400).json({ error: 'No changes detected' });
        }
        
        // Add updated_at
        updates.push('updated_at = CURRENT_TIMESTAMP');
        
        // Handle status-specific timestamps
        if (req.body.status === 'Resolved' && current.status !== 'Resolved') {
            updates.push('resolved_at = CURRENT_TIMESTAMP');
        } else if (req.body.status === 'Closed' && current.status !== 'Closed') {
            updates.push('closed_at = CURRENT_TIMESTAMP');
        }
        
        values.push(bugId);
        
        // Update bug
        await pool.execute(`
            UPDATE bugs SET ${updates.join(', ')} WHERE id = ?
        `, values);
        
        // Log activities
        for (const activity of activities) {
            await pool.execute(`
                INSERT INTO bug_activity_log (bug_id, user_id, action, field_name, old_value, new_value)
                VALUES (?, ?, ?, ?, ?, ?)
            `, [bugId, req.user.id, activity.action, activity.field_name, activity.old_value, activity.new_value]);
        }
        
        // Create notifications for watchers
        const [watchers] = await pool.execute(
            'SELECT user_id FROM bug_watchers WHERE bug_id = ? AND user_id != ?',
            [bugId, req.user.id]
        );
        
        for (const watcher of watchers) {
            await pool.execute(`
                INSERT INTO notifications (user_id, bug_id, title, message, type)
                VALUES (?, ?, ?, ?, 'bug_updated')
            `, [
                watcher.user_id, bugId,
                `Bug updated: ${current.title}`,
                `Bug #${bugId} has been updated`
            ]);
        }
        
        // If assignee changed, send email notification
        if (req.body.assigned_to && req.body.assigned_to !== current.assigned_to) {
            const [assignee] = await pool.execute(
                'SELECT email, username FROM users WHERE id = ?',
                [req.body.assigned_to]
            );

            if (assignee.length > 0) {
                await sendEmailNotification(
                    assignee[0].email,
                    `New Bug Assignment: ${current.title}`,
                    `You have been assigned to bug "${current.title}". Please review it at your earliest convenience.`
                );
            }
        }
        
        res.json({ message: 'Bug updated successfully' });
    } catch (error) {
        console.error('Update bug error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete bug (admin only)
app.delete('/api/bugs/:id', authenticateToken, requireRole(['admin']), [
    param('id').isInt().withMessage('Bug ID must be an integer')
], handleValidationErrors, async (req, res) => {
    try {
        const bugId = req.params.id;
        
        const [result] = await pool.execute('DELETE FROM bugs WHERE id = ?', [bugId]);
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Bug not found' });
        }
        
        res.json({ message: 'Bug deleted successfully' });
    } catch (error) {
        console.error('Delete bug error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ================================================
// Comments Routes
// ================================================

// Add comment to bug
app.post('/api/bugs/:id/comments', authenticateToken, [
    param('id').isInt().withMessage('Bug ID must be an integer'),
    body('comment').notEmpty().withMessage('Comment is required'),
    body('comment_type').optional().isIn(['comment', 'status_change', 'assignment'])
], handleValidationErrors, async (req, res) => {
    try {
        const bugId = req.params.id;
        const { comment, comment_type = 'comment', is_internal = false } = req.body;
        
        // Check if bug exists
        const [bugs] = await pool.execute('SELECT title FROM bugs WHERE id = ?', [bugId]);
        if (bugs.length === 0) {
            return res.status(404).json({ error: 'Bug not found' });
        }
        
        // Insert comment
        const [result] = await pool.execute(`
            INSERT INTO bug_comments (bug_id, user_id, comment, comment_type, is_internal)
            VALUES (?, ?, ?, ?, ?)
        `, [bugId, req.user.id, comment, comment_type, is_internal]);
        
        // Log activity
        await pool.execute(`
            INSERT INTO bug_activity_log (bug_id, user_id, action, description)
            VALUES (?, ?, 'commented', 'Added a comment')
        `, [bugId, req.user.id]);
        
        // Notify watchers (except commenter)
        const [watchers] = await pool.execute(
            'SELECT user_id FROM bug_watchers WHERE bug_id = ? AND user_id != ?',
            [bugId, req.user.id]
        );
        
        for (const watcher of watchers) {
            await pool.execute(`
                INSERT INTO notifications (user_id, bug_id, title, message, type)
                VALUES (?, ?, ?, ?, 'bug_commented')
            `, [
                watcher.user_id, bugId,
                `New comment on: ${bugs[0].title}`,
                `${req.user.username} commented on bug #${bugId}`
            ]);
        }
        
        res.status(201).json({
            message: 'Comment added successfully',
            commentId: result.insertId
        });
    } catch (error) {
        console.error('Add comment error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ================================================
// Attachments Routes
// ================================================

// Upload attachment
app.post('/api/bugs/:id/attachments', authenticateToken, upload.single('file'), [
    param('id').isInt().withMessage('Bug ID must be an integer')
], handleValidationErrors, async (req, res) => {
    try {
        const bugId = req.params.id;
        
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        
        // Check if bug exists
        const [bugs] = await pool.execute('SELECT id FROM bugs WHERE id = ?', [bugId]);
        if (bugs.length === 0) {
            return res.status(404).json({ error: 'Bug not found' });
        }
        
        // Insert attachment record
        const [result] = await pool.execute(`
            INSERT INTO bug_attachments (
                bug_id, filename, original_filename, file_path, 
                file_size, mime_type, description, uploaded_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            bugId, req.file.filename, req.file.originalname, req.file.path,
            req.file.size, req.file.mimetype, req.body.description || null, req.user.id
        ]);
        
        res.status(201).json({
            message: 'File uploaded successfully',
            attachmentId: result.insertId,
            filename: req.file.filename
        });
    } catch (error) {
        console.error('Upload attachment error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Download attachment
app.get('/api/attachments/:id', authenticateToken, [
    param('id').isInt().withMessage('Attachment ID must be an integer')
], handleValidationErrors, async (req, res) => {
    try {
        const attachmentId = req.params.id;
        
        const [attachments] = await pool.execute(
            'SELECT * FROM bug_attachments WHERE id = ?',
            [attachmentId]
        );
        
        if (attachments.length === 0) {
            return res.status(404).json({ error: 'Attachment not found' });
        }
        
        const attachment = attachments[0];
        const filePath = path.resolve(attachment.file_path);
        
        // Check if file exists
        try {
            await fs.access(filePath);
        } catch {
            return res.status(404).json({ error: 'File not found on server' });
        }
        
        res.setHeader('Content-Disposition', `attachment; filename="${attachment.original_filename}"`);
        res.setHeader('Content-Type', attachment.mime_type);
        res.sendFile(filePath);
    } catch (error) {
        console.error('Download attachment error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ================================================
// Projects Routes
// ================================================

// Get all projects
app.get('/api/projects', authenticateToken, async (req, res) => {
    try {
        const [projects] = await pool.execute(`
            SELECT 
                p.*,
                u.full_name as created_by_name,
                COUNT(DISTINCT b.id) as bug_count,
                COUNT(DISTINCT pm.user_id) as member_count
            FROM projects p
            LEFT JOIN users u ON p.created_by = u.id
            LEFT JOIN bugs b ON p.id = b.project_id
            LEFT JOIN project_members pm ON p.id = pm.project_id
            GROUP BY p.id
            ORDER BY p.created_at DESC
        `);
        
        res.json(projects);
    } catch (error) {
        console.error('Get projects error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Create new project
app.post('/api/projects', authenticateToken, requireRole(['admin', 'developer']), [
    body('name').notEmpty().withMessage('Project name is required'),
    body('description').optional().isString()
], handleValidationErrors, async (req, res) => {
    try {
        const { name, description } = req.body;
        
        const [result] = await pool.execute(
            'INSERT INTO projects (name, description, created_by) VALUES (?, ?, ?)',
            [name, description, req.user.id]
        );
        
        // Add creator as project owner
        await pool.execute(
            'INSERT INTO project_members (project_id, user_id, role) VALUES (?, ?, ?)',
            [result.insertId, req.user.id, 'owner']
        );
        
        res.status(201).json({
            message: 'Project created successfully',
            projectId: result.insertId
        });
    } catch (error) {
        console.error('Create project error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ================================================
// Dashboard/Statistics Routes
// ================================================

// Get dashboard statistics
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        // Get bug statistics
        const [bugStats] = await pool.execute(`
            SELECT 
                COUNT(*) as total_bugs,
                COUNT(CASE WHEN status = 'Open' THEN 1 END) as open_bugs,
                COUNT(CASE WHEN status = 'In Progress' THEN 1 END) as in_progress_bugs,
                COUNT(CASE WHEN status = 'Resolved' THEN 1 END) as resolved_bugs,
                COUNT(CASE WHEN status = 'Closed' THEN 1 END) as closed_bugs,
                COUNT(CASE WHEN severity = 'Critical' THEN 1 END) as critical_bugs,
                COUNT(CASE WHEN severity = 'High' THEN 1 END) as high_bugs,
                COUNT(CASE WHEN assigned_to = ? THEN 1 END) as my_bugs
            FROM bugs
        `, [req.user.id]);
        
        // Get recent bugs
        const [recentBugs] = await pool.execute(`
            SELECT 
                b.id, b.title, b.severity, b.status, b.created_at,
                p.name as project_name,
                u.full_name as created_by_name
            FROM bugs b
            LEFT JOIN projects p ON b.project_id = p.id
            LEFT JOIN users u ON b.created_by = u.id
            ORDER BY b.created_at DESC
            LIMIT 10
        `);
        
        // Get user activity
        const [userActivity] = await pool.execute(`
            SELECT 
                COUNT(DISTINCT b.id) as bugs_created,
                COUNT(DISTINCT b2.id) as bugs_assigned,
                COUNT(DISTINCT bc.id) as comments_made
            FROM users u
            LEFT JOIN bugs b ON u.id = b.created_by
            LEFT JOIN bugs b2 ON u.id = b2.assigned_to
            LEFT JOIN bug_comments bc ON u.id = bc.user_id
            WHERE u.id = ?
        `, [req.user.id]);
        
        res.json({
            bugStats: bugStats[0],
            recentBugs,
            userActivity: userActivity[0]
        });
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ================================================
// Notifications Routes
// ================================================

// Get user notifications
app.get('/api/notifications', authenticateToken, [
    query('limit').optional().isInt({ min: 1, max: 50 }).withMessage('Limit must be between 1 and 50')
], handleValidationErrors, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 20;
        
        const [notifications] = await pool.execute(`
            SELECT 
                n.*,
                b.title as bug_title
            FROM notifications n
            LEFT JOIN bugs b ON n.bug_id = b.id
            WHERE n.user_id = ?
            ORDER BY n.created_at DESC
            LIMIT ?
        `, [req.user.id, limit]);
        
        res.json(notifications);
    } catch (error) {
        console.error('Get notifications error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Mark notification as read
app.put('/api/notifications/:id/read', authenticateToken, [
    param('id').isInt().withMessage('Notification ID must be an integer')
], handleValidationErrors, async (req, res) => {
    try {
        const [result] = await pool.execute(`
            UPDATE notifications 
            SET is_read = TRUE, read_at = CURRENT_TIMESTAMP 
            WHERE id = ? AND user_id = ?
        `, [req.params.id, req.user.id]);
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Notification not found' });
        }
        
        res.json({ message: 'Notification marked as read' });
    } catch (error) {
        console.error('Mark notification read error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ================================================
// Error Handling Middleware
// ================================================
app.use('/api/ai', aiTagsRoute); // ✅ Mount AI route

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large' });
        }
    }
    
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// ================================================
// Server Startup
// ================================================

app.listen(PORT, async () => {
    try {
        await initializeDatabase();
        initializeNotificationSchedules(); // Add this line
        console.log(`Bug Tracker API server running on port ${PORT}`);
        console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    } catch (error) {
        console.error('Server startup failed:', error);
        process.exit(1);
    }
});

module.exports = app;

// Initialize notification schedules
function initializeNotificationSchedules() {
    // Check for due bugs every hour
    cron.schedule('0 * * * *', async () => {
        console.log('Running due bugs check...');
        await checkDueBugs();
    });

    // Check for overdue bugs daily at midnight
    cron.schedule('0 0 * * *', async () => {
        try {
            const [bugs] = await pool.execute(`
                SELECT b.*, u.email 
                FROM bugs b
                JOIN users u ON b.assigned_to = u.id
                WHERE b.due_date < NOW()
                AND b.status NOT IN ('Resolved', 'Closed')
                AND b.overdue_notification_sent = FALSE
            `);

            for (const bug of bugs) {
                await sendEmailNotification(
                    bug.email,
                    `Bug Overdue: ${bug.title}`,
                    `The bug "${bug.title}" is now overdue.`
                );

                await pool.execute(
                    'UPDATE bugs SET overdue_notification_sent = TRUE WHERE id = ?',
                    [bug.id]
                );
            }
        } catch (error) {
            console.error('Overdue bugs check error:', error);
        }
    });
}