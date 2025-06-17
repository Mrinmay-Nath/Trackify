const nodemailer = require('nodemailer');
const cron = require('node-cron');
const mysql = require('mysql2/promise');

// Email transporter configuration
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: process.env.SMTP_PORT || 587,
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

// Send email notification
async function sendEmailNotification(to, subject, text) {
    try {
        await transporter.sendMail({
            from: process.env.SMTP_FROM || 'noreply@bugtracker.com',
            to,
            subject,
            text
        });
    } catch (error) {
        console.error('Email notification error:', error);
    }
}

// Check for due bugs and notify users
async function checkDueBugs() {
    try {
        const [bugs] = await pool.execute(`
            SELECT b.*, u.email, u.username 
            FROM bugs b
            JOIN users u ON b.assigned_to = u.id
            WHERE b.due_date <= DATE_ADD(NOW(), INTERVAL 24 HOUR)
            AND b.status NOT IN ('Resolved', 'Closed')
            AND b.notification_sent = FALSE
        `);

        for (const bug of bugs) {
            // Send email notification
            await sendEmailNotification(
                bug.email,
                `Bug Due Soon: ${bug.title}`,
                `The bug "${bug.title}" is due within 24 hours.`
            );

            // Update notification status
            await pool.execute(
                'UPDATE bugs SET notification_sent = TRUE WHERE id = ?',
                [bug.id]
            );
        }
    } catch (error) {
        console.error('Due bugs check error:', error);
    }
}

module.exports = { sendEmailNotification, checkDueBugs };
