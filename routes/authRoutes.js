const express = require('express');
const router = express.Router();

// Import controllers
const authController = require('../controllers/authController');

// Import middleware
const { auth, deviceLock, limiters } = require('../middleware');

// Public routes (no authentication required)

// User login (code-based)
router.post('/user/login',
    limiters.loginLimiter,
    deviceLock.extractDeviceId,
    authController.userLogin
);

// SubAdmin login
router.post('/subadmin/login',
    limiters.loginLimiter,
    deviceLock.extractDeviceId,
    authController.subAdminLogin
);

// MainAdmin login
router.post('/mainadmin/login',
    limiters.loginLimiter,
    deviceLock.extractDeviceId,
    authController.mainAdminLogin
);

// Refresh token (uses refresh token middleware)
router.post('/refresh',
    limiters.authLimiter,
    deviceLock.extractDeviceId,
    auth.verifyRefreshToken,
    authController.refreshToken
);

// Protected routes (authentication required)

// Get current user profile
router.get('/profile',
    limiters.generalLimiter,
    deviceLock.extractDeviceId,
    auth.verifyToken,
    deviceLock.checkSingleDeviceLock,
    deviceLock.checkMultiDeviceLock,
    auth.verifyDevice,
    authController.getProfile
);

// Verify current session
router.get('/verify',
    limiters.generalLimiter,
    deviceLock.extractDeviceId,
    auth.verifyToken,
    deviceLock.checkSingleDeviceLock,
    deviceLock.checkMultiDeviceLock,
    auth.verifyDevice,
    authController.verifySession
);

// Logout from current device
router.post('/logout',
    limiters.generalLimiter,
    deviceLock.extractDeviceId,
    auth.verifyToken,
    deviceLock.checkSingleDeviceLock,
    deviceLock.checkMultiDeviceLock,
    auth.verifyDevice,
    authController.logout
);

// Logout from all devices (MainAdmin only)
router.post('/logout/all',
    limiters.generalLimiter,
    deviceLock.extractDeviceId,
    auth.verifyToken,
    deviceLock.checkSingleDeviceLock,
    deviceLock.checkMultiDeviceLock,
    auth.verifyDevice,
    authController.logoutAllDevices
);

// Change password (SubAdmin and MainAdmin only)
router.post('/change-password',
    limiters.passwordChangeLimiter,
    deviceLock.extractDeviceId,
    auth.verifyToken,
    deviceLock.checkSingleDeviceLock,
    deviceLock.checkMultiDeviceLock,
    auth.verifyDevice,
    authController.changePassword
);

// Health check for auth service
router.get('/health', (req, res) => {
    res.json({
        success: true,
        service: 'Authentication Service',
        status: 'healthy',
        timestamp: new Date().toISOString()
    });
});

module.exports = router;