const express = require('express');
const router = express.Router();

// Import all route modules
const authRoutes = require('./authRoutes');
const userRoutes = require('./userRoutes');
const subAdminRoutes = require('./subAdminRoutes');
const mainAdminRoutes = require('./mainAdminRoutes');

// Import middleware for general use
const { limiters } = require('../middleware');

// Apply general rate limiting to all routes
router.use(limiters.generalLimiter);

// API Health Check
router.get('/health', (req, res) => {
    res.json({
        success: true,
        message: 'MERN User Management API is running',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        services: {
            authentication: 'active',
            userManagement: 'active',
            subAdminManagement: 'active',
            mainAdminPanel: 'active',
            database: 'connected'
        }
    });
});

// API Documentation endpoint
router.get('/docs', (req, res) => {
    res.json({
        success: true,
        message: 'API Documentation',
        endpoints: {
            authentication: {
                base: '/api/auth',
                endpoints: [
                    'POST /user/login - User login with code',
                    'POST /subadmin/login - SubAdmin login',
                    'POST /mainadmin/login - MainAdmin login',
                    'POST /refresh - Refresh access token',
                    'GET /profile - Get current user profile',
                    'POST /logout - Logout from current device',
                    'POST /logout/all - Logout from all devices (MainAdmin)',
                    'POST /change-password - Change password'
                ]
            },
            users: {
                base: '/api/users',
                endpoints: [
                    'GET /dashboard - User dashboard (User only)',
                    'POST / - Create new user (SubAdmin)',
                    'GET /my-users - Get my users (SubAdmin)',
                    'GET /search - Search users (SubAdmin)',
                    'GET /:userId - Get user details',
                    'PUT /:userId/package - Update user package',
                    'DELETE /:userId - Delete user'
                ]
            },
            subAdmins: {
                base: '/api/subadmins',
                endpoints: [
                    'GET /dashboard - SubAdmin dashboard',
                    'POST / - Create sub-admin (MainAdmin)',
                    'GET / - Get all sub-admins (MainAdmin)',
                    'GET /:subAdminId - Get sub-admin details',
                    'PUT /:subAdminId/payment - Update payment',
                    'PUT /:subAdminId/status - Toggle status',
                    'PUT /:subAdminId/reset-password - Reset password',
                    'DELETE /:subAdminId - Delete sub-admin'
                ]
            },
            mainAdmin: {
                base: '/api/admin',
                endpoints: [
                    'GET /dashboard - Main admin dashboard',
                    'GET /analytics - System analytics',
                    'GET /health - System health status',
                    'PUT /crash-value - Update crash value',
                    'POST /force-logout - Force logout user',
                    'GET /logs - Get system logs',
                    'GET /security-events - Get security events'
                ]
            }
        },
        authentication: {
            method: 'JWT Bearer Token',
            refreshToken: 'HTTP-only cookie',
            deviceLocking: 'Enabled (1 device for User/SubAdmin, 3 for MainAdmin)'
        },
        rateLimiting: {
            general: '100 requests per 15 minutes',
            authentication: '5 attempts per 15 minutes',
            login: '3 attempts per 15 minutes per IP+username',
            userCreation: '20 users per hour per sub-admin'
        }
    });
});

// Mount route modules
router.use('/auth', authRoutes);
router.use('/users', userRoutes);
router.use('/subadmins', subAdminRoutes);
router.use('/admin', mainAdminRoutes);

// 404 handler for API routes
router.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'API endpoint not found',
        requestedUrl: req.originalUrl,
        availableEndpoints: [
            '/api/auth/*',
            '/api/users/*',
            '/api/subadmins/*',
            '/api/admin/*'
        ],
        documentation: '/api/docs'
    });
});

module.exports = router;