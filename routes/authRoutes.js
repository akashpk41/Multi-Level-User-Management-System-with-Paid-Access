const express = require('express');
const router = express.Router();

// Import controllers
const authController = require('../controllers/authController');

// Import middleware
const {
    auth,
    deviceLock,
    limiters,
    authenticateAndVerifyDevice,
    adminAuth
} = require('../middleware');

// Login Routes
router.post('/login/user',
    deviceLock.extractDeviceId,
    limiters.loginLimiter,
    authController.userLogin
);

router.post('/login/subadmin',
    deviceLock.extractDeviceId,
    limiters.loginLimiter,
    authController.subAdminLogin
);

router.post('/login/mainadmin',
    deviceLock.extractDeviceId,
    limiters.loginLimiter,
    authController.mainAdminLogin
);

// Logout Routes
router.post('/logout',
    authenticateAndVerifyDevice,
    authController.logout
);

router.post('/logout-all-devices',
    authenticateAndVerifyDevice,
    authController.logoutAllDevices
);

// Token Management
router.post('/refresh-token',
    deviceLock.extractDeviceId,
    auth.verifyRefreshToken,
    authController.refreshToken
);

// User Information
router.get('/me',
    authenticateAndVerifyDevice,
    limiters.generalLimiter,
    authController.getCurrentUser
);

router.get('/check-status',
    authenticateAndVerifyDevice,
    authController.checkAuthStatus
);

// Admin Actions
router.post('/force-logout',
    adminAuth,
    limiters.generalLimiter,
    authController.forceLogout
);

// Health check for auth service
router.get('/health', (req, res) => {
    res.json({
        success: true,
        service: 'Authentication Service',
        status: 'Running',
        timestamp: new Date().toISOString()
    });
});

module.exports = router;