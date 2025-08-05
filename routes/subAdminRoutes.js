const express = require('express');
const router = express.Router();

// Import controllers
const subAdminController = require('../controllers/subAdminController');

// Import middleware
const {
    subAdminAuth,
    mainAdminAuth,
    role,
    limiters
} = require('../middleware');

// Routes for SubAdmins (accessed by logged-in sub-admins)

// SubAdmin dashboard (SubAdmin only)
router.get('/dashboard',
    limiters.dashboardLimiter,
    subAdminAuth,
    subAdminController.getSubAdminDashboard
);

// Routes for MainAdmin (sub-admin management)

// Create new sub-admin (MainAdmin only)
router.post('/',
    limiters.subAdminCreationLimiter,
    mainAdminAuth,
    subAdminController.createSubAdmin
);

// Get all sub-admins (MainAdmin only)
router.get('/',
    limiters.generalLimiter,
    mainAdminAuth,
    subAdminController.getAllSubAdmins
);

// Get single sub-admin details (MainAdmin only)
router.get('/:subAdminId',
    limiters.generalLimiter,
    mainAdminAuth,
    role.canManageSubAdmin,
    subAdminController.getSubAdminById
);

// Update sub-admin payment (MainAdmin only)
router.put('/:subAdminId/payment',
    limiters.generalLimiter,
    mainAdminAuth,
    role.canManageSubAdmin,
    subAdminController.updateSubAdminPayment
);

// Activate/Deactivate sub-admin (MainAdmin only)
router.put('/:subAdminId/status',
    limiters.generalLimiter,
    mainAdminAuth,
    role.canManageSubAdmin,
    subAdminController.toggleSubAdminStatus
);

// Reset sub-admin password (MainAdmin only)
router.put('/:subAdminId/reset-password',
    limiters.passwordChangeLimiter,
    mainAdminAuth,
    role.canManageSubAdmin,
    subAdminController.resetSubAdminPassword
);

// Delete sub-admin (MainAdmin only)
router.delete('/:subAdminId',
    limiters.generalLimiter,
    mainAdminAuth,
    role.canManageSubAdmin,
    subAdminController.deleteSubAdmin
);

// Export router
module.exports = router;