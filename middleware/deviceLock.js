const { ActivityLog } = require('../models');
const crypto = require('crypto');

// Generate unique device ID based on request headers
const generateDeviceId = (req) => {
    const userAgent = req.get('User-Agent') || '';
    const acceptLanguage = req.get('Accept-Language') || '';
    const acceptEncoding = req.get('Accept-Encoding') || '';
    const ip = req.ip || '';

    // Create a hash from browser fingerprint
    const fingerprint = `${userAgent}-${acceptLanguage}-${acceptEncoding}-${ip}`;
    return crypto.createHash('sha256').update(fingerprint).digest('hex').substring(0, 32);
};

// Extract or generate device ID
const extractDeviceId = (req, res, next) => {
    try {
        // Priority order: header > body > auto-generate
        let deviceId = req.headers['x-device-id'] ||
                      req.body.deviceId ||
                      req.query.deviceId;

        if (!deviceId) {
            deviceId = generateDeviceId(req);
        }

        req.deviceId = deviceId;
        req.generatedDeviceId = !req.headers['x-device-id'] && !req.body.deviceId && !req.query.deviceId;

        // Add device info to response headers
        res.setHeader('X-Device-ID', deviceId);

        next();
    } catch (error) {
        console.error('Device ID extraction error:', error);
        next();
    }
};

// Check device lock for Users and SubAdmins (single device policy)
const checkSingleDeviceLock = async (req, res, next) => {
    try {
        const { user, userRole, deviceId } = req;

        if (userRole === 'mainadmin') {
            // Main admin has different device policy
            return next();
        }

        if (!user || (userRole !== 'user' && userRole !== 'subadmin')) {
            return next();
        }

        // Check if device is locked to another device
        if (user.deviceId && user.deviceId !== deviceId) {
            // Log device lock violation
            await ActivityLog.logAuth({
                userId: user._id,
                userModel: userRole === 'user' ? 'User' : 'SubAdmin',
                userName: user.name,
                username: user.username || user.code,
                action: 'device_lock_violation',
                description: `Attempted access from different device. Locked device: ${user.deviceId}, Attempted device: ${deviceId}`,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                deviceId: deviceId,
                status: 'failed',
                severity: 'high'
            });

            return res.status(401).json({
                success: false,
                message: 'Device not authorized. Please login from your registered device.',
                deviceLocked: true,
                lockedDeviceId: user.deviceId.substring(0, 8) + '...' // Partial device ID for security
            });
        }

        // If no device is set, this is the first login - set device
        if (!user.deviceId) {
            user.deviceId = deviceId;
            await user.save();

            // Log device registration
            await ActivityLog.logAuth({
                userId: user._id,
                userModel: userRole === 'user' ? 'User' : 'SubAdmin',
                userName: user.name,
                username: user.username || user.code,
                action: 'device_registered',
                description: `Device registered for user`,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                deviceId: deviceId,
                status: 'success',
                severity: 'low'
            });
        }

        next();
    } catch (error) {
        console.error('Single device lock check error:', error);
        res.status(500).json({
            success: false,
            message: 'Device lock check failed'
        });
    }
};

// Check device lock for Main Admin (multiple device policy)
const checkMultiDeviceLock = async (req, res, next) => {
    try {
        const { user, userRole, deviceId } = req;

        if (userRole !== 'mainadmin') {
            return next();
        }

        if (!user || !user.devices) {
            return next();
        }

        // Find device in registered devices
        const deviceIndex = user.devices.findIndex(d => d.deviceId === deviceId);

        if (deviceIndex === -1) {
            // Device not registered
            if (user.devices.length >= user.maxDevices) {
                // Maximum devices reached
                return res.status(401).json({
                    success: false,
                    message: `Maximum ${user.maxDevices} devices allowed. Please logout from another device first.`,
                    maxDevicesReached: true,
                    registeredDevices: user.devices.length
                });
            }

            // Register new device
            const deviceInfo = {
                deviceId: deviceId,
                deviceName: getDeviceName(req.get('User-Agent')),
                userAgent: req.get('User-Agent'),
                ip: req.ip,
                lastActive: new Date(),
                refreshToken: null // Will be set during login
            };

            user.devices.push(deviceInfo);
            await user.save();

            // Log new device registration
            await ActivityLog.logAuth({
                userId: user._id,
                userModel: 'MainAdmin',
                userName: user.name,
                username: user.username,
                action: 'device_registered',
                description: `New device registered: ${deviceInfo.deviceName}`,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                deviceId: deviceId,
                status: 'success',
                severity: 'medium'
            });
        } else {
            // Update device activity
            user.devices[deviceIndex].lastActive = new Date();
            user.devices[deviceIndex].ip = req.ip;
            await user.save();
        }

        next();
    } catch (error) {
        console.error('Multi device lock check error:', error);
        res.status(500).json({
            success: false,
            message: 'Device lock check failed'
        });
    }
};

// Get device name from user agent
const getDeviceName = (userAgent) => {
    if (!userAgent) return 'Unknown Device';

    const ua = userAgent.toLowerCase();

    // Mobile devices
    if (ua.includes('android')) return 'Android Device';
    if (ua.includes('iphone')) return 'iPhone';
    if (ua.includes('ipad')) return 'iPad';
    if (ua.includes('mobile')) return 'Mobile Device';

    // Desktop browsers
    if (ua.includes('chrome')) return 'Chrome Browser';
    if (ua.includes('firefox')) return 'Firefox Browser';
    if (ua.includes('safari') && !ua.includes('chrome')) return 'Safari Browser';
    if (ua.includes('edge')) return 'Edge Browser';
    if (ua.includes('opera')) return 'Opera Browser';

    // Operating systems
    if (ua.includes('windows')) return 'Windows Computer';
    if (ua.includes('macintosh')) return 'Mac Computer';
    if (ua.includes('linux')) return 'Linux Computer';

    return 'Unknown Device';
};

// Force logout from all devices (admin action)
const logoutAllDevices = async (user, userRole, reason = 'admin_action') => {
    try {
        if (userRole === 'mainadmin') {
            // Clear all devices
            user.devices = [];
        } else {
            // Clear single device
            user.deviceId = null;
            user.refreshToken = null;
        }

        user.isAutoLoggedOut = true;
        user.autoLogoutReason = reason;

        await user.save();

        // If it's a sub-admin, also logout all their users
        if (userRole === 'subadmin') {
            const { User } = require('../models');
            await User.updateMany(
                { subAdmin: user._id },
                {
                    deviceId: null,
                    refreshToken: null,
                    isActive: false,
                    isAutoLoggedOut: true,
                    autoLogoutReason: 'sub_admin_logout'
                }
            );
        }

        return true;
    } catch (error) {
        console.error('Logout all devices error:', error);
        return false;
    }
};

// Logout from specific device (main admin only)
const logoutFromDevice = async (user, deviceId, reason = 'manual') => {
    try {
        if (!user.devices) return false;

        const deviceIndex = user.devices.findIndex(d => d.deviceId === deviceId);

        if (deviceIndex !== -1) {
            user.devices.splice(deviceIndex, 1);
            await user.save();

            // Log device logout
            await ActivityLog.logAuth({
                userId: user._id,
                userModel: 'MainAdmin',
                userName: user.name,
                username: user.username,
                action: 'device_logout',
                description: `Logged out from device: ${deviceId}`,
                deviceId: deviceId,
                status: 'success',
                severity: 'low'
            });

            return true;
        }

        return false;
    } catch (error) {
        console.error('Logout from device error:', error);
        return false;
    }
};

// Middleware to clean up inactive devices (for main admin)
const cleanupInactiveDevices = async (req, res, next) => {
    try {
        if (req.userRole === 'mainadmin' && req.user.devices) {
            const now = new Date();
            const inactiveThreshold = 7 * 24 * 60 * 60 * 1000; // 7 days

            const activeDevices = req.user.devices.filter(device => {
                return (now - device.lastActive) < inactiveThreshold;
            });

            if (activeDevices.length !== req.user.devices.length) {
                req.user.devices = activeDevices;
                await req.user.save();

                // Log cleanup
                await ActivityLog.logAuth({
                    userId: req.user._id,
                    userModel: 'MainAdmin',
                    userName: req.user.name,
                    username: req.user.username,
                    action: 'inactive_devices_cleaned',
                    description: `Cleaned up ${req.user.devices.length - activeDevices.length} inactive devices`,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    deviceId: req.deviceId,
                    status: 'success',
                    severity: 'low'
                });
            }
        }

        next();
    } catch (error) {
        console.error('Cleanup inactive devices error:', error);
        next(); // Continue even if cleanup fails
    }
};

// Get user's device information
const getUserDevices = (user, userRole) => {
    if (userRole === 'mainadmin') {
        return user.devices.map(device => ({
            deviceId: device.deviceId.substring(0, 8) + '...',
            deviceName: device.deviceName,
            ip: device.ip,
            lastActive: device.lastActive,
            isCurrentDevice: false // Will be set by calling function
        }));
    } else {
        return user.deviceId ? [{
            deviceId: user.deviceId.substring(0, 8) + '...',
            deviceName: getDeviceName(user.userAgent || ''),
            lastActive: user.lastLogin,
            isCurrentDevice: true
        }] : [];
    }
};

module.exports = {
    extractDeviceId,
    checkSingleDeviceLock,
    checkMultiDeviceLock,
    logoutAllDevices,
    logoutFromDevice,
    cleanupInactiveDevices,
    getUserDevices,
    getDeviceName,
    generateDeviceId
};