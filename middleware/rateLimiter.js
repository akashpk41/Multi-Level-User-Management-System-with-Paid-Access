const rateLimit = require('express-rate-limit');
const { ActivityLog } = require('../models');

// Create custom rate limit handler
const createRateLimitHandler = (message = 'Too many requests') => {
    return async (req, res) => {
        try {
            // Log rate limit exceeded
            if (req.user) {
                await ActivityLog.logAuth({
                    userId: req.user._id,
                    userModel: req.userRole === 'user' ? 'User' : req.userRole === 'subadmin' ? 'SubAdmin' : 'MainAdmin',
                    userName: req.user.name,
                    username: req.user.username || req.user.code,
                    action: 'rate_limit_exceeded',
                    description: `Rate limit exceeded for ${req.method} ${req.originalUrl}`,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    deviceId: req.deviceId,
                    status: 'failed',
                    severity: 'medium'
                });
            }
        } catch (error) {
            console.error('Error logging rate limit:', error);
        }

        res.status(429).json({
            success: false,
            message,
            retryAfter: req.rateLimit.resetTime
        });
    };
};

// General API rate limiting
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
        success: false,
        message: 'Too many requests from this IP, please try again later.',
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: createRateLimitHandler('Too many requests from this IP, please try again later.')
});

// Authentication rate limiting (stricter)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 auth requests per windowMs
    skipSuccessfulRequests: true, // Only count failed requests
    message: {
        success: false,
        message: 'Too many authentication attempts, please try again later.',
    },
    handler: createRateLimitHandler('Too many authentication attempts, please try again later.')
});

// Login rate limiting (very strict)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 3, // Limit each IP to 3 login attempts per windowMs
    skipSuccessfulRequests: true,
    keyGenerator: (req) => {
        // Rate limit by IP + username combination
        const identifier = req.body.username || req.body.code || req.ip;
        return `${req.ip}-${identifier}`;
    },
    message: {
        success: false,
        message: 'Too many login attempts, please try again after 15 minutes.',
    },
    handler: createRateLimitHandler('Too many login attempts, please try again after 15 minutes.')
});

// User creation rate limiting (for sub-admins)
const userCreationLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 20, // Maximum 20 users per hour per sub-admin
    keyGenerator: (req) => {
        // Rate limit per user ID
        return req.user ? req.user._id.toString() : req.ip;
    },
    message: {
        success: false,
        message: 'User creation limit reached. Maximum 20 users per hour.',
    },
    handler: createRateLimitHandler('User creation limit reached. Maximum 20 users per hour.')
});

// Sub-admin creation rate limiting (for main admin)
const subAdminCreationLimiter = rateLimit({
    windowMs: 24 * 60 * 60 * 1000, // 24 hours
    max: 10, // Maximum 10 sub-admins per day
    keyGenerator: (req) => {
        return req.user ? req.user._id.toString() : req.ip;
    },
    message: {
        success: false,
        message: 'Sub-admin creation limit reached. Maximum 10 sub-admins per day.',
    },
    handler: createRateLimitHandler('Sub-admin creation limit reached. Maximum 10 sub-admins per day.')
});

// Search rate limiting
const searchLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 30, // Maximum 30 searches per minute
    keyGenerator: (req) => {
        return req.user ? req.user._id.toString() : req.ip;
    },
    message: {
        success: false,
        message: 'Search limit reached. Please wait before searching again.',
    },
    handler: createRateLimitHandler('Search limit reached. Please wait before searching again.')
});

// Dashboard/Analytics rate limiting
const dashboardLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 10, // Maximum 10 dashboard requests per minute
    keyGenerator: (req) => {
        return req.user ? req.user._id.toString() : req.ip;
    },
    message: {
        success: false,
        message: 'Dashboard access limit reached. Please wait before refreshing.',
    },
    handler: createRateLimitHandler('Dashboard access limit reached. Please wait before refreshing.')
});

// Role-based rate limiting
const roleBasedLimiter = (req, res, next) => {
    const role = req.rateLimitRole || 'guest';

    // Different limits based on role
    const limits = {
        guest: { windowMs: 15 * 60 * 1000, max: 20 },
        user: { windowMs: 15 * 60 * 1000, max: 50 },
        subadmin: { windowMs: 15 * 60 * 1000, max: 100 },
        mainadmin: { windowMs: 15 * 60 * 1000, max: 200 }
    };

    const limit = limits[role] || limits.guest;

    const limiter = rateLimit({
        windowMs: limit.windowMs,
        max: limit.max,
        keyGenerator: (req) => {
            const userId = req.user ? req.user._id.toString() : '';
            return `${req.ip}-${role}-${userId}`;
        },
        message: {
            success: false,
            message: `Rate limit exceeded for ${role} role.`,
        },
        handler: createRateLimitHandler(`Rate limit exceeded for ${role} role.`)
    });

    limiter(req, res, next);
};

// Device-based rate limiting
const deviceLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200, // Maximum requests per device
    keyGenerator: (req) => {
        const deviceId = req.headers['x-device-id'] || req.deviceId || req.ip;
        return `device-${deviceId}`;
    },
    message: {
        success: false,
        message: 'Device rate limit exceeded.',
    },
    handler: createRateLimitHandler('Device rate limit exceeded.')
});

// Crash value update rate limiting (security sensitive)
const crashValueLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // Maximum 5 crash value updates per hour
    keyGenerator: (req) => {
        return req.user ? req.user._id.toString() : req.ip;
    },
    message: {
        success: false,
        message: 'Crash value update limit reached. Maximum 5 updates per hour.',
    },
    handler: createRateLimitHandler('Crash value update limit reached. Maximum 5 updates per hour.')
});

// Password change rate limiting
const passwordChangeLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // Maximum 3 password changes per hour
    keyGenerator: (req) => {
        return req.user ? req.user._id.toString() : req.ip;
    },
    message: {
        success: false,
        message: 'Password change limit reached. Maximum 3 changes per hour.',
    },
    handler: createRateLimitHandler('Password change limit reached. Maximum 3 changes per hour.')
});

// Export all limiters
module.exports = {
    generalLimiter,
    authLimiter,
    loginLimiter,
    userCreationLimiter,
    subAdminCreationLimiter,
    searchLimiter,
    dashboardLimiter,
    roleBasedLimiter,
    deviceLimiter,
    crashValueLimiter,
    passwordChangeLimiter,
    createRateLimitHandler
};