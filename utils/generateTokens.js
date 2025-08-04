const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Generate access token
const generateAccessToken = (payload) => {
    return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
        expiresIn: process.env.JWT_ACCESS_EXPIRE || '15m'
    });
};

// Generate refresh token
const generateRefreshToken = (payload) => {
    return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
        expiresIn: process.env.JWT_REFRESH_EXPIRE || '7d'
    });
};

// Generate token pair for User
const generateUserTokens = (user, deviceId) => {
    const payload = {
        id: user._id,
        role: 'user',
        code: user.code,
        deviceId: deviceId,
        subAdminId: user.subAdmin
    };

    return {
        accessToken: generateAccessToken(payload),
        refreshToken: generateRefreshToken(payload)
    };
};

// Generate token pair for SubAdmin
const generateSubAdminTokens = (subAdmin, deviceId) => {
    const payload = {
        id: subAdmin._id,
        role: 'subadmin',
        username: subAdmin.username,
        deviceId: deviceId,
        isPaid: subAdmin.isPaid,
        isActive: subAdmin.isActive
    };

    return {
        accessToken: generateAccessToken(payload),
        refreshToken: generateRefreshToken(payload)
    };
};

// Generate token pair for MainAdmin
const generateMainAdminTokens = (mainAdmin, deviceId) => {
    const payload = {
        id: mainAdmin._id,
        role: 'mainadmin',
        username: mainAdmin.username,
        deviceId: deviceId
    };

    return {
        accessToken: generateAccessToken(payload),
        refreshToken: generateRefreshToken(payload)
    };
};

// Generate tokens based on user role
const generateTokensByRole = (user, role, deviceId) => {
    switch (role) {
        case 'user':
            return generateUserTokens(user, deviceId);
        case 'subadmin':
            return generateSubAdminTokens(user, deviceId);
        case 'mainadmin':
            return generateMainAdminTokens(user, deviceId);
        default:
            throw new Error('Invalid user role');
    }
};

// Set secure cookies for tokens
const setTokenCookies = (res, tokens, options = {}) => {
    const defaultOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/'
    };

    // Access token cookie (shorter expiry)
    res.cookie('accessToken', tokens.accessToken, {
        ...defaultOptions,
        maxAge: 15 * 60 * 1000, // 15 minutes
        ...options.accessToken
    });

    // Refresh token cookie (longer expiry)
    res.cookie('refreshToken', tokens.refreshToken, {
        ...defaultOptions,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        ...options.refreshToken
    });
};

// Clear token cookies
const clearTokenCookies = (res) => {
    const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/'
    };

    res.clearCookie('accessToken', cookieOptions);
    res.clearCookie('refreshToken', cookieOptions);
};

// Verify and decode token without expiry check
const decodeTokenWithoutVerify = (token) => {
    try {
        return jwt.decode(token);
    } catch (error) {
        return null;
    }
};

// Generate unique session ID
const generateSessionId = () => {
    return crypto.randomBytes(32).toString('hex');
};

// Generate secure random code for users
const generateUserCode = (length = 8) => {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';

    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }

    return result;
};

// Generate temporary password for sub-admins
const generateTempPassword = (length = 12) => {
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*';

    const allChars = uppercase + lowercase + numbers + symbols;
    let password = '';

    // Ensure at least one character from each category
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += symbols[Math.floor(Math.random() * symbols.length)];

    // Fill remaining length
    for (let i = 4; i < length; i++) {
        password += allChars[Math.floor(Math.random() * allChars.length)];
    }

    // Shuffle password
    return password.split('').sort(() => Math.random() - 0.5).join('');
};

// Extract token from request
const extractTokenFromRequest = (req) => {
    let token = null;

    // Check Authorization header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
        token = req.headers.authorization.split(' ')[1];
    }
    // Check cookies
    else if (req.cookies && req.cookies.accessToken) {
        token = req.cookies.accessToken;
    }

    return token;
};

// Get token expiry time
const getTokenExpiry = (token) => {
    try {
        const decoded = jwt.decode(token);
        return decoded ? new Date(decoded.exp * 1000) : null;
    } catch (error) {
        return null;
    }
};

// Check if token is about to expire (within next 5 minutes)
const isTokenExpiringSoon = (token) => {
    const expiry = getTokenExpiry(token);
    if (!expiry) return true;

    const fiveMinutesFromNow = new Date(Date.now() + 5 * 60 * 1000);
    return expiry <= fiveMinutesFromNow;
};

// Generate device fingerprint hash
const generateDeviceFingerprint = (userAgent, acceptLanguage, acceptEncoding, ip) => {
    const fingerprint = `${userAgent || ''}-${acceptLanguage || ''}-${acceptEncoding || ''}-${ip || ''}`;
    return crypto.createHash('sha256').update(fingerprint).digest('hex').substring(0, 32);
};

// Token validation utilities
const validateTokenStructure = (token) => {
    if (!token || typeof token !== 'string') return false;

    const parts = token.split('.');
    return parts.length === 3; // JWT has 3 parts
};

// Create login response object
const createLoginResponse = (user, role, tokens, deviceId) => {
    let userInfo;

    switch (role) {
        case 'user':
            userInfo = {
                id: user._id,
                name: user.name,
                code: user.code,
                package: user.package,
                packageExpiry: user.packageExpiry,
                remainingTime: user.remainingTime,
                isExpired: user.isExpired,
                subAdmin: user.subAdmin
            };
            break;

        case 'subadmin':
            userInfo = {
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
                activeUsers: user.activeUsers
            };
            break;

        case 'mainadmin':
            userInfo = {
                id: user._id,
                name: user.name,
                username: user.username,
                email: user.email,
                crashValue: user.crashValue,
                totalSubAdmins: user.totalSubAdmins,
                totalUsers: user.totalUsers,
                maxDevices: user.maxDevices,
                devicesCount: user.devices ? user.devices.length : 0
            };
            break;

        default:
            userInfo = { id: user._id, name: user.name };
    }

    return {
        success: true,
        message: 'Login successful',
        user: userInfo,
        role: role,
        deviceId: deviceId.substring(0, 8) + '...', // Partial device ID for security
        tokens: {
            accessToken: tokens.accessToken,
            // Don't send refresh token in response body for security
            expiresIn: process.env.JWT_ACCESS_EXPIRE || '15m'
        }
    };
};

module.exports = {
    generateAccessToken,
    generateRefreshToken,
    generateUserTokens,
    generateSubAdminTokens,
    generateMainAdminTokens,
    generateTokensByRole,
    setTokenCookies,
    clearTokenCookies,
    decodeTokenWithoutVerify,
    generateSessionId,
    generateUserCode,
    generateTempPassword,
    extractTokenFromRequest,
    getTokenExpiry,
    isTokenExpiringSoon,
    generateDeviceFingerprint,
    validateTokenStructure,
    createLoginResponse
};