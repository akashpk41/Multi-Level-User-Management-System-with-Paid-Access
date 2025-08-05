const express = require('express');
const router = express.Router();

// Import controllers
const userController = require('../controllers/userController');

// Import middleware
const {
    userAuth,
    subAdminAuth,
    adminAuth,
    role,
    limiters
} = require('../middleware');

// Routes for Users (accessed by logged-in users)

// User dashboard (user only)
router.get('/dashboard',
    limiters.dashboardLimiter,
    userAuth,
    userController.getUserDashboard
);

// Routes for SubAdmins (user management)

// Create new user (SubAdmin only)
router.post('/',
    limiters.userCreationLimiter,
    subAdminAuth,
    userController.createUser
);

// Get all users for current sub-admin
router.get('/my-users',
    limiters.generalLimiter,
    subAdminAuth,
    userController.getMyUsers
);

// Search users (SubAdmin only)
router.get('/search',
    limiters.searchLimiter,
    subAdminAuth,
    userController.searchUsers
);

// Get single user details (SubAdmin or MainAdmin)
router.get('/:userId',
    limiters.generalLimiter,
    adminAuth,
    role.canManageUser,
    userController.getUserById
);

// Update user package (SubAdmin or MainAdmin)
router.put('/:userId/package',
    limiters.generalLimiter,
    adminAuth,
    role.canManageUser,
    userController.updateUserPackage
);

// Delete user (SubAdmin or MainAdmin)
router.delete('/:userId',
    limiters.generalLimiter,
    adminAuth,
    role.canManageUser,
    userController.deleteUser
);

// Export router
module.exports = router;