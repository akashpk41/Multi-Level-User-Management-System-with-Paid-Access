const { User, SubAdmin, MainAdmin, ActivityLog } = require('../models');
const {
    generateTokensByRole,
    setTokenCookies,
    clearTokenCookies,
    createLoginResponse,
    generateDeviceFingerprint
} = require('../utils/generateTokens');

// Helper function to get device name
const getDeviceName = (userAgent) => {
    if (!userAgent) return 'Unknown Device';

    const ua = userAgent.toLowerCase();

    if (ua.includes('android')) return 'Android Device';
    if (ua.includes('iphone')) return 'iPhone';
    if (ua.includes('ipad')) return 'iPad';
    if (ua.includes('mobile')) return 'Mobile Device';
    if (ua.includes('chrome')) return 'Chrome Browser';
    if (ua.includes('firefox')) return 'Firefox Browser';
    if (ua.includes('safari') && !ua.includes('chrome')) return 'Safari Browser';
    if (ua.includes('edge')) return 'Edge Browser';

    return 'Desktop Computer';
};

// User Login (Code-based)
const userLogin = async (req, res) => {
    try {
        const { code, deviceId } = req.body;

        if (!code) {
            return res.status(400).json({
                success: false,
                message: 'User code is required'
            });
        }

        // Find user by code
        const user = await User.findOne({
            code: code.toUpperCase()
        }).populate('subAdmin', 'name username isActive isPaid paymentExpiry');

        if (!user) {
            // Log failed login attempt
            await ActivityLog.logAuth({
                userId: null,
                userModel: 'User',
                userName: 'Unknown',
                code: code.toUpperCase(),
                action: 'failed_login',
                description: `Failed login attempt with invalid code: ${code}`,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                deviceId: deviceId || req.deviceId,
                status: 'failed',
                severity: 'medium'
            });

            return res.status(401).json({
                success: false,
                message: 'Invalid user code'
            });
        }

        // Check if user is active
        if (!user.isActive) {
            return res.status(401).json({
                success: false,
                message: 'User account is inactive'
            });
        }

        // Check if package is expired
        if (user.isExpired) {
            user.checkAndAutoLogout();
            await user.save();

            return res.status(401).json({
                success: false,
                message: 'Your package has expired. Please contact your sub-admin.',
                packageExpired: true
            });
        }

        // Check if sub-admin is active and has valid payment
        if (!user.subAdmin || !user.subAdmin.isActive || user.subAdmin.isPaymentExpired) {
            return res.status(401).json({
                success: false,
                message: 'Your sub-admin account is inactive or expired. Please contact support.',
                subAdminInactive: true
            });
        }

        const finalDeviceId = deviceId || req.deviceId;

        // Check device lock
        if (user.deviceId && user.deviceId !== finalDeviceId) {
            // Log device lock violation
            await ActivityLog.logAuth({
                userId: user._id,
                userModel: 'User',
                userName: user.name,
                code: user.code,
                action: 'device_lock_violation',
                description: `Login attempt from different device`,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                deviceId: finalDeviceId,
                status: 'failed',
                severity: 'high'
            });

            return res.status(401).json({
                success: false,
                message: 'You can only login from one device at a time.',
                deviceLocked: true
            });
        }

        // Generate tokens
        const tokens = generateTokensByRole(user, 'user', finalDeviceId);

        // Update user login info
        user.deviceId = finalDeviceId;
        user.refreshToken = tokens.refreshToken;
        user.lastLogin = new Date();
        user.loginCount += 1;
        user.isActive = true;
        user.isAutoLoggedOut = false;
        user.autoLogoutReason = null;

        await user.save();

        // Set secure cookies
        setTokenCookies(res, tokens);

        // Log successful login
        await ActivityLog.logAuth({
            userId: user._id,
            userModel: 'User',
            userName: user.name,
            code: user.code,
            action: 'login',
            description: 'User logged in successfully',
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            deviceId: finalDeviceId,
            status: 'success',
            severity: 'low'
        });

        // Create response
        const response = createLoginResponse(user, 'user', tokens, finalDeviceId);

        res.json(response);
    } catch (error) {
        console.error('User login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed. Please try again.'
        });
    }
};

// SubAdmin Login
const subAdminLogin = async (req, res) => {
    try {
        const { username, password, deviceId } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }

        // Find sub-admin
        const subAdmin = await SubAdmin.findOne({
            username: username.toLowerCase()
        });

        if (!subAdmin) {
            // Log failed login attempt
            await ActivityLog.logAuth({
                userId: null,
                userModel: 'SubAdmin',
                userName: 'Unknown',
                username: username,
                action: 'failed_login',
                description: `Failed login attempt with invalid username: ${username}`,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                deviceId: deviceId || req.deviceId,
                status: 'failed',
                severity: 'medium'
            });

            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        // Check password
        const isPasswordValid = await subAdmin.comparePassword(password);

        if (!isPasswordValid) {
            // Log failed password attempt
            await ActivityLog.logAuth({
                userId: subAdmin._id,
                userModel: 'SubAdmin',
                userName: subAdmin.name,
                username: subAdmin.username,
                action: 'failed_login',
                description: 'Failed login attempt with invalid password',
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                deviceId: deviceId || req.deviceId,
                status: 'failed',
                severity: 'high'
            });

            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        // Check if sub-admin can access (active + paid + not expired)
        if (!subAdmin.canAccess) {
            let message = 'Account is inactive.';

            if (!subAdmin.isActive) {
                message = 'Your account is inactive. Please contact main admin.';
            } else if (!subAdmin.isPaid) {
                message = 'Payment required. Please contact main admin.';
            } else if (subAdmin.isPaymentExpired) {
                message = 'Your payment has expired. Please contact main admin.';
            }

            return res.status(401).json({
                success: false,
                message: message,
                accountInactive: true
            });
        }

        const finalDeviceId = deviceId || req.deviceId;

        // Check device lock
        if (subAdmin.deviceId && subAdmin.deviceId !== finalDeviceId) {
            // Log device lock violation
            await ActivityLog.logAuth({
                userId: subAdmin._id,
                userModel: 'SubAdmin',
                userName: subAdmin.name,
                username: subAdmin.username,
                action: 'device_lock_violation',
                description: 'Login attempt from different device',
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                deviceId: finalDeviceId,
                status: 'failed',
                severity: 'high'
            });

            return res.status(401).json({
                success: false,
                message: 'You can only login from one device at a time.',
                deviceLocked: true
            });
        }

        // Generate tokens
        const tokens = generateTokensByRole(subAdmin, 'subadmin', finalDeviceId);

        // Update sub-admin login info
        subAdmin.deviceId = finalDeviceId;
        subAdmin.refreshToken = tokens.refreshToken;
        subAdmin.lastLogin = new Date();
        subAdmin.loginCount += 1;
        subAdmin.isAutoLoggedOut = false;
        subAdmin.autoLogoutReason = null;

        await subAdmin.save();

        // Set secure cookies
        setTokenCookies(res, tokens);

        // Log successful login
        await ActivityLog.logAuth({
            userId: subAdmin._id,
            userModel: 'SubAdmin',
            userName: subAdmin.name,
            username: subAdmin.username,
            action: 'login',
            description: 'Sub-admin logged in successfully',
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            deviceId: finalDeviceId,
            status: 'success',
            severity: 'low'
        });

        // Create response
        const response = createLoginResponse(subAdmin, 'subadmin', tokens, finalDeviceId);

        res.json(response);
    } catch (error) {
        console.error('SubAdmin login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed. Please try again.'
        });
    }
};

// MainAdmin Login
const mainAdminLogin = async (req, res) => {
    try {
        const { username, password, deviceId } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }

        // Find main admin
        const mainAdmin = await MainAdmin.findOne({
            username: username.toLowerCase()
        });

        if (!mainAdmin) {
            // Log failed login attempt
            await ActivityLog.logAuth({
                userId: null,
                userModel: 'MainAdmin',
                userName: 'Unknown',
                username: username,
                action: 'failed_login',
                description: `Failed main admin login attempt with invalid username: ${username}`,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                deviceId: deviceId || req.deviceId,
                status: 'failed',
                severity: 'critical'
            });

            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        // Check password
        const isPasswordValid = await mainAdmin.comparePassword(password);

        if (!isPasswordValid) {
            // Log failed password attempt
            await ActivityLog.logAuth({
                userId: mainAdmin._id,
                userModel: 'MainAdmin',
                userName: mainAdmin.name,
                username: mainAdmin.username,
                action: 'failed_login',
                description: 'Failed main admin login attempt with invalid password',
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                deviceId: deviceId || req.deviceId,
                status: 'failed',
                severity: 'critical'
            });

            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        // Check if main admin is active
        if (!mainAdmin.isActive) {
            return res.status(401).json({
                success: false,
                message: 'Main admin account is inactive'
            });
        }

        const finalDeviceId = deviceId || req.deviceId;

        // Check device limit (max 3 devices for main admin)
        const existingDeviceIndex = mainAdmin.devices.findIndex(d => d.deviceId === finalDeviceId);

        if (existingDeviceIndex === -1 && mainAdmin.devices.length >= mainAdmin.maxDevices) {
            return res.status(401).json({
                success: false,
                message: `Maximum ${mainAdmin.maxDevices} devices allowed. Please logout from another device first.`,
                maxDevicesReached: true
            });
        }

        // Generate tokens
        const tokens = generateTokensByRole(mainAdmin, 'mainadmin', finalDeviceId);

        // Update or add device
        if (existingDeviceIndex !== -1) {
            // Update existing device
            mainAdmin.devices[existingDeviceIndex].refreshToken = tokens.refreshToken;
            mainAdmin.devices[existingDeviceIndex].lastActive = new Date();
            mainAdmin.devices[existingDeviceIndex].ip = req.ip;
        } else {
            // Add new device
            mainAdmin.devices.push({
                deviceId: finalDeviceId,
                deviceName: getDeviceName(req.get('User-Agent')),
                userAgent: req.get('User-Agent'),
                ip: req.ip,
                lastActive: new Date(),
                refreshToken: tokens.refreshToken
            });
        }

        // Update main admin login info
        mainAdmin.lastLogin = new Date();
        mainAdmin.loginCount += 1;

        await mainAdmin.save();

        // Set secure cookies
        setTokenCookies(res, tokens);

        // Log successful login
        await ActivityLog.logAuth({
            userId: mainAdmin._id,
            userModel: 'MainAdmin',
            userName: mainAdmin.name,
            username: mainAdmin.username,
            action: 'login',
            description: 'Main admin logged in successfully',
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            deviceId: finalDeviceId,
            status: 'success',
            severity: 'medium'
        });

        // Create response
        const response = createLoginResponse(mainAdmin, 'mainadmin', tokens, finalDeviceId);

        res.json(response);
    } catch (error) {
        console.error('MainAdmin login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed. Please try again.'
        });
    }
};

// Logout (All roles)
const logout = async (req, res) => {
    try {
        const { user, userRole, deviceId } = req;

        if (userRole === 'mainadmin') {
            // Remove specific device from main admin
            const deviceIndex = user.devices.findIndex(d => d.deviceId === deviceId);
            if (deviceIndex !== -1) {
                user.devices.splice(deviceIndex, 1);
            }
        } else {
            // Clear device for user/subadmin
            user.deviceId = null;
            user.refreshToken = null;
        }

        await user.save();

        // Clear cookies
        clearTokenCookies(res);

        // Log logout
        await ActivityLog.logAuth({
            userId: user._id,
            userModel: userRole === 'user' ? 'User' : userRole === 'subadmin' ? 'SubAdmin' : 'MainAdmin',
            userName: user.name,
            username: user.username || user.code,
            action: 'logout',
            description: 'User logged out successfully',
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            deviceId: deviceId,
            status: 'success',
            severity: 'low'
        });

        res.json({
            success: true,
            message: 'Logged out successfully'
        });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({
            success: false,
            message: 'Logout failed'
        });
    }
};

// Logout from all devices (Main Admin only)
const logoutAllDevices = async (req, res) => {
    try {
        const { user, userRole } = req;

        if (userRole !== 'mainadmin') {
            return res.status(403).json({
                success: false,
                message: 'Only main admin can logout from all devices'
            });
        }

        // Clear all devices
        user.devices = [];
        await user.save();

        // Clear cookies
        clearTokenCookies(res);

        // Log logout all
        await ActivityLog.logAuth({
            userId: user._id,
            userModel: 'MainAdmin',
            userName: user.name,
            username: user.username,
            action: 'logout_all_devices',
            description: 'Main admin logged out from all devices',
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            status: 'success',
            severity: 'medium'
        });

        res.json({
            success: true,
            message: 'Logged out from all devices successfully'
        });
    } catch (error) {
        console.error('Logout all devices error:', error);
        res.status(500).json({
            success: false,
            message: 'Logout from all devices failed'
        });
    }
};

// Refresh Token
const refreshToken = async (req, res) => {
    try {
        const { user, userRole, deviceId, refreshToken: currentRefreshToken } = req;

        // Generate new tokens
        const tokens = generateTokensByRole(user, userRole, deviceId);

        // Update refresh token in database
        if (userRole === 'mainadmin') {
            const deviceIndex = user.devices.findIndex(d => d.deviceId === deviceId);
            if (deviceIndex !== -1) {
                user.devices[deviceIndex].refreshToken = tokens.refreshToken;
                user.devices[deviceIndex].lastActive = new Date();
            }
        } else {
            user.refreshToken = tokens.refreshToken;
        }

        await user.save();

        // Set new cookies
        setTokenCookies(res, tokens);

        // Log token refresh
        await ActivityLog.logAuth({
            userId: user._id,
            userModel: userRole === 'user' ? 'User' : userRole === 'subadmin' ? 'SubAdmin' : 'MainAdmin',
            userName: user.name,
            username: user.username || user.code,
            action: 'token_refresh',
            description: 'Access token refreshed successfully',
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            deviceId: deviceId,
            status: 'success',
            severity: 'low'
        });

        res.json({
            success: true,
            message: 'Token refreshed successfully',
            tokens: {
                accessToken: tokens.accessToken,
                expiresIn: process.env.JWT_ACCESS_EXPIRE || '15m'
            }
        });
    } catch (error) {
        console.error('Token refresh error:', error);
        res.status(500).json({
            success: false,
            message: 'Token refresh failed'
        });
    }
};

// Get current user profile
const getProfile = async (req, res) => {
    try {
        const { user, userRole } = req;

        let userProfile;

        switch (userRole) {
            case 'user':
                await user.populate('subAdmin', 'name username');
                userProfile = {
                    id: user._id,
                    name: user.name,
                    code: user.code,
                    package: user.package,
                    packageExpiry: user.packageExpiry,
                    remainingTime: user.remainingTime,
                    isExpired: user.isExpired,
                    lastLogin: user.lastLogin,
                    loginCount: user.loginCount,
                    subAdmin: user.subAdmin
                };
                break;

            case 'subadmin':
                userProfile = {
                    id: user._id,
                    name: user.name,
                    username: user.username,
                    email: user.email,
                    phone: user.phone,
                    isPaid: user.isPaid,
                    paymentExpiry: user.paymentExpiry,
                    remainingPaymentTime: user.remainingPaymentTime,
                    isActive: user.isActive,
                    totalUsersAdded: user.totalUsersAdded,
                    activeUsers: user.activeUsers,
                    lastLogin: user.lastLogin,
                    loginCount: user.loginCount
                };
                break;

            case 'mainadmin':
                userProfile = {
                    id: user._id,
                    name: user.name,
                    username: user.username,
                    email: user.email,
                    crashValue: user.crashValue,
                    totalSubAdmins: user.totalSubAdmins,
                    totalUsers: user.totalUsers,
                    maxDevices: user.maxDevices,
                    devicesCount: user.devices ? user.devices.length : 0,
                    lastLogin: user.lastLogin,
                    loginCount: user.loginCount,
                    devices: user.devices ? user.devices.map(device => ({
                        deviceId: device.deviceId.substring(0, 8) + '...',
                        deviceName: device.deviceName,
                        lastActive: device.lastActive,
                        ip: device.ip
                    })) : []
                };
                break;
        }

        res.json({
            success: true,
            user: userProfile,
            role: userRole
        });
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get profile'
        });
    }
};

// Verify current session
const verifySession = async (req, res) => {
    try {
        const { user, userRole, deviceId } = req;

        // Check if user is still valid
        let isValid = true;
        let message = 'Session is valid';

        if (userRole === 'user') {
            if (user.isExpired) {
                isValid = false;
                message = 'Package expired';
            } else if (!user.isActive) {
                isValid = false;
                message = 'User inactive';
            }
        } else if (userRole === 'subadmin') {
            if (!user.canAccess) {
                isValid = false;
                message = 'Sub-admin account expired or inactive';
            }
        } else if (userRole === 'mainadmin') {
            if (!user.isActive) {
                isValid = false;
                message = 'Main admin account inactive';
            }
        }

        res.json({
            success: true,
            valid: isValid,
            message: message,
            user: {
                id: user._id,
                name: user.name,
                role: userRole
            },
            deviceId: deviceId.substring(0, 8) + '...'
        });
    } catch (error) {
        console.error('Verify session error:', error);
        res.status(500).json({
            success: false,
            message: 'Session verification failed'
        });
    }
};

// Change password (SubAdmin and MainAdmin only)
const changePassword = async (req, res) => {
    try {
        const { user, userRole } = req;
        const { currentPassword, newPassword } = req.body;

        if (userRole === 'user') {
            return res.status(403).json({
                success: false,
                message: 'Users cannot change password'
            });
        }

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Current password and new password are required'
            });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'New password must be at least 6 characters long'
            });
        }

        // Verify current password
        const isCurrentPasswordValid = await user.comparePassword(currentPassword);

        if (!isCurrentPasswordValid) {
            // Log failed password change attempt
            await ActivityLog.logAuth({
                userId: user._id,
                userModel: userRole === 'subadmin' ? 'SubAdmin' : 'MainAdmin',
                userName: user.name,
                username: user.username,
                action: 'password_change_failed',
                description: 'Failed password change attempt with invalid current password',
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                deviceId: req.deviceId,
                status: 'failed',
                severity: 'high'
            });

            return res.status(401).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }

        // Update password
        user.password = newPassword;
        await user.save();

        // Log successful password change
        await ActivityLog.logAuth({
            userId: user._id,
            userModel: userRole === 'subadmin' ? 'SubAdmin' : 'MainAdmin',
            userName: user.name,
            username: user.username,
            action: 'password_changed',
            description: 'Password changed successfully',
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            deviceId: req.deviceId,
            status: 'success',
            severity: 'medium'
        });

        res.json({
            success: true,
            message: 'Password changed successfully'
        });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({
            success: false,
            message: 'Password change failed'
        });
    }
};

module.exports = {
    userLogin,
    subAdminLogin,
    mainAdminLogin,
    logout,
    logoutAllDevices,
    refreshToken,
    getProfile,
    verifySession,
    changePassword
};