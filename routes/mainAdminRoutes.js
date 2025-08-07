const express = require('express');
const router = express.Router();

// Import controllers
const mainAdminController = require('../controllers/mainAdminController');

// Import middleware
const {
    mainAdminAuth,
    limiters
} = require('../middleware');

// Dashboard & Analytics Routes (MainAdmin only)

// Main admin dashboard
router.get('/dashboard',
    limiters.dashboardLimiter,
    mainAdminAuth,
    mainAdminController.getMainAdminDashboard
);

// System analytics with charts
router.get('/analytics',
    limiters.dashboardLimiter,
    mainAdminAuth,
    mainAdminController.getSystemAnalytics
);

// System health status
router.get('/health',
    limiters.generalLimiter,
    mainAdminAuth,
    mainAdminController.getSystemHealth
);

// System Management Routes (MainAdmin only)

// Update crash value
router.put('/crash-value',
    limiters.crashValueLimiter,
    mainAdminAuth,
    mainAdminController.updateCrashValue
);

// Force logout user/subadmin (emergency action)
router.post('/force-logout',
    limiters.generalLimiter,
    mainAdminAuth,
    mainAdminController.forceLogoutUser
);

// Package Management Routes (MainAdmin only)

// Get current package prices
router.get('/package-prices',
    limiters.generalLimiter,
    mainAdminAuth,
    mainAdminController.getPackagePrices
);

// Update package prices
router.put('/package-prices',
    limiters.generalLimiter,
    mainAdminAuth,
    mainAdminController.updatePackagePrices
);

// Get sales analytics
router.get('/sales-analytics',
    limiters.dashboardLimiter,
    mainAdminAuth,
    mainAdminController.getSalesAnalytics
);

// Monitoring & Logs Routes (MainAdmin only)

// Get system logs with filters
router.get('/logs',
    limiters.generalLimiter,
    mainAdminAuth,
    mainAdminController.getSystemLogs
);

// Get security events (high priority logs)
router.get('/security-events',
    limiters.generalLimiter,
    mainAdminAuth,
    mainAdminController.getSecurityEvents
);

// Export router
module.exports = router;