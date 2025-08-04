const { ActivityLog } = require('../models');

// Check if user has required role
const authorize = (...roles) => {
    return async (req, res, next) => {
        try {
            if (!req.user || !req.userRole) {
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required'
                });
            }

            if (!roles.includes(req.userRole)) {
                // Log unauthorized access attempt
                await ActivityLog.logAuth({
                    userId: req.user._id,
                    userModel: req.userRole === 'user' ? 'User' : req.userRole === 'subadmin' ? 'SubAdmin' : 'MainAdmin',
                    userName: req.user.name,
                    username: req.user.username || req.user.code,
                    action: 'unauthorized_access',
                    description: `Attempted to access ${req.method} ${req.originalUrl} without proper role. Required: ${roles.join(', ')}, Has: ${req.userRole}`,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    deviceId: req.deviceId,
                    status: 'failed',
                    severity: 'high'
                });

                return res.status(403).json({
                    success: false,
                    message: `Access denied. Required role: ${roles.join(' or ')}`
                });
            }

            next();
        } catch (error) {
            console.error('Authorization error:', error);
            res.status(500).json({
                success: false,
                message: 'Authorization check failed'
            });
        }
    };
};

// Main Admin only access
const onlyMainAdmin = authorize('mainadmin');

// Sub Admin and Main Admin access
const adminAccess = authorize('subadmin', 'mainadmin');

// Only Sub Admin access (not main admin)
const onlySubAdmin = authorize('subadmin');

// Only User access
const onlyUser = authorize('user');

// User and Sub Admin access (not main admin)
const userAndSubAdmin = authorize('user', 'subadmin');

// All roles access
const allRoles = authorize('user', 'subadmin', 'mainadmin');

// Check if sub-admin can manage specific user
const canManageUser = async (req, res, next) => {
    try {
        if (req.userRole === 'mainadmin') {
            // Main admin can manage all users
            return next();
        }

        if (req.userRole !== 'subadmin') {
            return res.status(403).json({
                success: false,
                message: 'Only sub-admin or main admin can manage users'
            });
        }

        // Check if the user belongs to this sub-admin
        const { User } = require('../models');
        const userId = req.params.userId || req.params.id || req.body.userId;

        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'User ID is required'
            });
        }

        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (user.subAdmin.toString() !== req.user._id.toString()) {
            // Log unauthorized user management attempt
            await ActivityLog.logAuth({
                userId: req.user._id,
                userModel: 'SubAdmin',
                userName: req.user.name,
                username: req.user.username,
                action: 'unauthorized_user_access',
                description: `Attempted to manage user ${user.name} (${user.code}) belonging to different sub-admin`,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                deviceId: req.deviceId,
                status: 'failed',
                severity: 'high'
            });

            return res.status(403).json({
                success: false,
                message: 'You can only manage your own users'
            });
        }

        // Attach user to request for further use
        req.targetUser = user;
        next();
    } catch (error) {
        console.error('User management authorization error:', error);
        res.status(500).json({
            success: false,
            message: 'User management authorization failed'
        });
    }
};

// Check if main admin can manage specific sub-admin
const canManageSubAdmin = async (req, res, next) => {
    try {
        if (req.userRole !== 'mainadmin') {
            return res.status(403).json({
                success: false,
                message: 'Only main admin can manage sub-admins'
            });
        }

        const { SubAdmin } = require('../models');
        const subAdminId = req.params.subAdminId || req.params.id || req.body.subAdminId;

        if (!subAdminId) {
            return res.status(400).json({
                success: false,
                message: 'Sub-admin ID is required'
            });
        }

        const subAdmin = await SubAdmin.findById(subAdminId);

        if (!subAdmin) {
            return res.status(404).json({
                success: false,
                message: 'Sub-admin not found'
            });
        }

        // Attach sub-admin to request
        req.targetSubAdmin = subAdmin;
        next();
    } catch (error) {
        console.error('Sub-admin management authorization error:', error);
        res.status(500).json({
            success: false,
            message: 'Sub-admin management authorization failed'
        });
    }
};

// Check if user owns the resource (for self-management)
const ownResource = async (req, res, next) => {
    try {
        const resourceId = req.params.id || req.params.userId || req.body.userId;

        if (!resourceId) {
            return res.status(400).json({
                success: false,
                message: 'Resource ID is required'
            });
        }

        // Check if user is accessing their own resource
        if (req.user._id.toString() !== resourceId.toString()) {
            return res.status(403).json({
                success: false,
                message: 'You can only access your own resources'
            });
        }

        next();
    } catch (error) {
        console.error('Resource ownership error:', error);
        res.status(500).json({
            success: false,
            message: 'Resource ownership check failed'
        });
    }
};

// Check rate limiting based on role
const roleBasedRateLimit = (req, res, next) => {
    // Set rate limit info based on role
    req.rateLimitRole = req.userRole || 'guest';
    next();
};

// Middleware to check if sub-admin has active subscription
const checkSubAdminSubscription = async (req, res, next) => {
    try {
        if (req.userRole !== 'subadmin') {
            return next();
        }

        if (!req.user.canAccess) {
            // Log subscription check failure
            await ActivityLog.logAuth({
                userId: req.user._id,
                userModel: 'SubAdmin',
                userName: req.user.name,
                username: req.user.username,
                action: 'subscription_check_failed',
                description: `Sub-admin attempted action without active subscription`,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                deviceId: req.deviceId,
                status: 'failed',
                severity: 'medium'
            });

            return res.status(403).json({
                success: false,
                message: 'Your subscription has expired. Please contact main admin.',
                subscriptionExpired: true
            });
        }

        next();
    } catch (error) {
        console.error('Subscription check error:', error);
        res.status(500).json({
            success: false,
            message: 'Subscription check failed'
        });
    }
};

// Middleware to check if user has valid package
const checkUserPackage = async (req, res, next) => {
    try {
        if (req.userRole !== 'user') {
            return next();
        }

        if (req.user.isExpired) {
            // Log package expiry
            await ActivityLog.logAuth({
                userId: req.user._id,
                userModel: 'User',
                userName: req.user.name,
                code: req.user.code,
                action: 'package_expired_access',
                description: `User attempted action with expired package`,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                deviceId: req.deviceId,
                status: 'failed',
                severity: 'medium'
            });

            return res.status(403).json({
                success: false,
                message: 'Your package has expired. Please contact your sub-admin.',
                packageExpired: true
            });
        }

        next();
    } catch (error) {
        console.error('Package check error:', error);
        res.status(500).json({
            success: false,
            message: 'Package check failed'
        });
    }
};

module.exports = {
    authorize,
    onlyMainAdmin,
    adminAccess,
    onlySubAdmin,
    onlyUser,
    userAndSubAdmin,
    allRoles,
    canManageUser,
    canManageSubAdmin,
    ownResource,
    roleBasedRateLimit,
    checkSubAdminSubscription,
    checkUserPackage
};