const jwt = require('jsonwebtoken');
const { User, SubAdmin, MainAdmin, ActivityLog } = require('../models');

// Verify JWT Access Token
const verifyToken = async (req, res, next) => {
    try {
        let token;

        // Get token from header
        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        }
        // Get token from cookies (backup)
        else if (req.cookies.accessToken) {
            token = req.cookies.accessToken;
        }

        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Access denied. No token provided.'
            });
        }

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

        // Find user based on role
        let user;
        switch (decoded.role) {
            case 'user':
                user = await User.findById(decoded.id).populate('subAdmin', 'name username isActive');
                break;
            case 'subadmin':
                user = await SubAdmin.findById(decoded.id);
                break;
            case 'mainadmin':
                user = await MainAdmin.findById(decoded.id);
                break;
            default:
                return res.status(401).json({
                    success: false,
                    message: 'Invalid token role'
                });
        }

        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Token is valid but user not found'
            });
        }

        // Check if user is active
        if (decoded.role === 'user' && (!user.isActive || user.isExpired)) {
            // Auto logout expired user
            if (user.isExpired) {
                user.checkAndAutoLogout();
                await user.save();
            }

            return res.status(401).json({
                success: false,
                message: 'User account expired or inactive',
                shouldLogout: true
            });
        }

        if (decoded.role === 'subadmin' && !user.canAccess) {
            // Auto logout if payment expired or inactive
            await user.checkAndAutoLogout();
            await user.save();

            return res.status(401).json({
                success: false,
                message: 'Sub-admin account expired or inactive',
                shouldLogout: true
            });
        }

        if (decoded.role === 'mainadmin' && !user.isActive) {
            return res.status(401).json({
                success: false,
                message: 'Main admin account is inactive'
            });
        }

        // Attach user to request
        req.user = user;
        req.userRole = decoded.role;
        req.deviceId = decoded.deviceId;

        next();
    } catch (error) {
        console.error('Token verification error:', error);

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                message: 'Invalid token'
            });
        }

        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Token expired',
                shouldRefresh: true
            });
        }

        res.status(500).json({
            success: false,
            message: 'Token verification failed'
        });
    }
};

// Device Lock Verification
const verifyDevice = async (req, res, next) => {
    try {
        const { user, userRole, deviceId } = req;
        const currentDeviceId = req.headers['x-device-id'] || deviceId;

        if (!currentDeviceId) {
            return res.status(401).json({
                success: false,
                message: 'Device ID is required'
            });
        }

        let isValidDevice = false;

        if (userRole === 'mainadmin') {
            // Main admin can have multiple devices
            isValidDevice = user.devices.some(device =>
                device.deviceId === currentDeviceId &&
                device.refreshToken // Has active session
            );
        } else {
            // User and SubAdmin can only have one device
            isValidDevice = user.deviceId === currentDeviceId;
        }

        if (!isValidDevice) {
            // Log suspicious activity
            await ActivityLog.logAuth({
                userId: user._id,
                userModel: userRole === 'user' ? 'User' : userRole === 'subadmin' ? 'SubAdmin' : 'MainAdmin',
                userName: user.name,
                username: user.username || user.code,
                action: 'device_change_logout',
                description: `Attempted access from unauthorized device: ${currentDeviceId}`,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                deviceId: currentDeviceId,
                status: 'failed',
                severity: 'high'
            });

            return res.status(401).json({
                success: false,
                message: 'Device not authorized. Please login again.',
                shouldLogout: true
            });
        }

        // Update last activity for main admin devices
        if (userRole === 'mainadmin') {
            const deviceIndex = user.devices.findIndex(d => d.deviceId === currentDeviceId);
            if (deviceIndex !== -1) {
                user.devices[deviceIndex].lastActive = new Date();
                user.devices[deviceIndex].ip = req.ip;
                await user.save();
            }
        }

        next();
    } catch (error) {
        console.error('Device verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Device verification failed'
        });
    }
};

// Optional Authentication (for public routes that can benefit from user context)
const optionalAuth = async (req, res, next) => {
    try {
        let token;

        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        } else if (req.cookies.accessToken) {
            token = req.cookies.accessToken;
        }

        if (token) {
            try {
                const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

                let user;
                switch (decoded.role) {
                    case 'user':
                        user = await User.findById(decoded.id);
                        break;
                    case 'subadmin':
                        user = await SubAdmin.findById(decoded.id);
                        break;
                    case 'mainadmin':
                        user = await MainAdmin.findById(decoded.id);
                        break;
                }

                if (user) {
                    req.user = user;
                    req.userRole = decoded.role;
                    req.deviceId = decoded.deviceId;
                }
            } catch (error) {
                // Token invalid, but continue without user context
                console.log('Optional auth token invalid:', error.message);
            }
        }

        next();
    } catch (error) {
        // Continue without authentication
        next();
    }
};

// Check if user has valid refresh token
const verifyRefreshToken = async (req, res, next) => {
    try {
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return res.status(401).json({
                success: false,
                message: 'Refresh token not found'
            });
        }

        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

        // Find user and verify refresh token
        let user;
        switch (decoded.role) {
            case 'user':
                user = await User.findById(decoded.id);
                break;
            case 'subadmin':
                user = await SubAdmin.findById(decoded.id);
                break;
            case 'mainadmin':
                user = await MainAdmin.findById(decoded.id);
                break;
        }

        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check refresh token validity
        let validRefreshToken = false;

        if (decoded.role === 'mainadmin') {
            // Check in devices array
            validRefreshToken = user.devices.some(device =>
                device.refreshToken === refreshToken &&
                device.deviceId === decoded.deviceId
            );
        } else {
            // Check single refresh token
            validRefreshToken = user.refreshToken === refreshToken;
        }

        if (!validRefreshToken) {
            return res.status(401).json({
                success: false,
                message: 'Invalid refresh token'
            });
        }

        req.user = user;
        req.userRole = decoded.role;
        req.deviceId = decoded.deviceId;
        req.refreshToken = refreshToken;

        next();
    } catch (error) {
        console.error('Refresh token verification error:', error);

        if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired refresh token'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Refresh token verification failed'
        });
    }
};

module.exports = {
    verifyToken,
    verifyDevice,
    optionalAuth,
    verifyRefreshToken
};