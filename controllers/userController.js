const { User, SubAdmin, ActivityLog } = require('../models');
const { generateUserCode } = require('../utils/generateTokens');
const { getPackageExpiry, getRemainingTime, formatDate } = require('../utils/dateUtil');

// Create new user (SubAdmin only)
const createUser = async (req, res) => {
    try {
        const { name, code, package: packageType } = req.body;
        const subAdminId = req.user._id;

        // Validation
        if (!name || !packageType) {
            return res.status(400).json({
                success: false,
                message: 'Name and package type are required'
            });
        }

        if (!['24h', '3d', '7d'].includes(packageType)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid package type. Must be 24h, 3d, or 7d'
            });
        }

        // Generate code if not provided
        let userCode = code;
        if (!userCode) {
            userCode = generateUserCode();

            // Ensure code is unique
            let attempts = 0;
            while (attempts < 10) {
                const existingUser = await User.findOne({ code: userCode });
                if (!existingUser) break;
                userCode = generateUserCode();
                attempts++;
            }

            if (attempts >= 10) {
                return res.status(500).json({
                    success: false,
                    message: 'Failed to generate unique code. Please try again.'
                });
            }
        } else {
            // Check if provided code is unique
            const existingUser = await User.findOne({ code: userCode.toUpperCase() });
            if (existingUser) {
                return res.status(400).json({
                    success: false,
                    message: 'User code already exists'
                });
            }
        }

        // Create user
        const user = new User({
            name: name.trim(),
            code: userCode.toUpperCase(),
            subAdmin: subAdminId,
            package: packageType,
            packageExpiry: getPackageExpiry(packageType)
        });

        await user.save();

        // Update sub-admin stats
        await SubAdmin.findByIdAndUpdate(subAdminId, {
            $inc: {
                totalUsersAdded: 1,
                activeUsers: 1
            }
        });

        // Log user creation
        await ActivityLog.logUserManagement({
            adminId: subAdminId,
            adminModel: 'SubAdmin',
            adminName: req.user.name,
            adminUsername: req.user.username,
            targetId: user._id,
            targetModel: 'User',
            targetName: user.name,
            targetIdentifier: user.code,
            action: 'user_created',
            description: `Created user ${user.name} with code ${user.code} and ${packageType} package`,
            metadata: {
                package: packageType,
                packageExpiry: user.packageExpiry
            },
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.status(201).json({
            success: true,
            message: 'User created successfully',
            user: {
                id: user._id,
                name: user.name,
                code: user.code,
                package: user.package,
                packageExpiry: user.packageExpiry,
                remainingTime: getRemainingTime(user.packageExpiry),
                isActive: user.isActive,
                createdAt: user.createdAt
            }
        });
    } catch (error) {
        console.error('Create user error:', error);

        if (error.code === 11000) {
            return res.status(400).json({
                success: false,
                message: 'User code already exists'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Failed to create user'
        });
    }
};

// Get all users for SubAdmin
const getMyUsers = async (req, res) => {
    try {
        const subAdminId = req.user._id;
        const {
            page = 1,
            limit = 10,
            search = '',
            status = 'all',
            package: packageFilter = 'all',
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;

        // Build query
        let query = { subAdmin: subAdminId };

        // Search by name or code
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { code: { $regex: search.toUpperCase(), $options: 'i' } }
            ];
        }

        // Filter by status
        if (status === 'active') {
            query.isActive = true;
            query.packageExpiry = { $gt: new Date() };
        } else if (status === 'expired') {
            query.packageExpiry = { $lte: new Date() };
        } else if (status === 'inactive') {
            query.isActive = false;
        }

        // Filter by package
        if (packageFilter && packageFilter !== 'all') {
            query.package = packageFilter;
        }

        // Sort options
        const sortOptions = {};
        sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;

        // Execute query with pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);

        const [users, totalCount] = await Promise.all([
            User.find(query)
                .sort(sortOptions)
                .skip(skip)
                .limit(parseInt(limit))
                .select('-refreshToken -__v'),
            User.countDocuments(query)
        ]);

        // Format users data
        const formattedUsers = users.map(user => ({
            id: user._id,
            name: user.name,
            code: user.code,
            package: user.package,
            packageExpiry: user.packageExpiry,
            remainingTime: getRemainingTime(user.packageExpiry),
            isActive: user.isActive,
            isExpired: user.isExpired,
            lastLogin: user.lastLogin,
            loginCount: user.loginCount,
            deviceId: user.deviceId ? user.deviceId.substring(0, 8) + '...' : null,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt
        }));

        // Get stats
        const stats = await User.aggregate([
            { $match: { subAdmin: subAdminId } },
            {
                $group: {
                    _id: null,
                    total: { $sum: 1 },
                    active: {
                        $sum: {
                            $cond: [
                                {
                                    $and: [
                                        { $eq: ['$isActive', true] },
                                        { $gt: ['$packageExpiry', new Date()] }
                                    ]
                                },
                                1,
                                0
                            ]
                        }
                    },
                    expired: {
                        $sum: {
                            $cond: [
                                { $lte: ['$packageExpiry', new Date()] },
                                1,
                                0
                            ]
                        }
                    },
                    inactive: {
                        $sum: {
                            $cond: [
                                { $eq: ['$isActive', false] },
                                1,
                                0
                            ]
                        }
                    }
                }
            }
        ]);

        const userStats = stats[0] || { total: 0, active: 0, expired: 0, inactive: 0 };

        res.json({
            success: true,
            users: formattedUsers,
            pagination: {
                currentPage: parseInt(page),
                totalPages: Math.ceil(totalCount / parseInt(limit)),
                totalCount,
                hasNext: skip + users.length < totalCount,
                hasPrev: parseInt(page) > 1
            },
            stats: userStats,
            filters: {
                search,
                status,
                package: packageFilter,
                sortBy,
                sortOrder
            }
        });
    } catch (error) {
        console.error('Get my users error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch users'
        });
    }
};

// Get single user details
const getUserById = async (req, res) => {
    try {
        const { userId } = req.params;
        const user = req.targetUser; // Set by canManageUser middleware

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Log user view
        await ActivityLog.logUserManagement({
            adminId: req.user._id,
            adminModel: req.userRole === 'subadmin' ? 'SubAdmin' : 'MainAdmin',
            adminName: req.user.name,
            adminUsername: req.user.username,
            targetId: user._id,
            targetModel: 'User',
            targetName: user.name,
            targetIdentifier: user.code,
            action: 'user_viewed',
            description: `Viewed user details: ${user.name} (${user.code})`,
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            success: true,
            user: {
                id: user._id,
                name: user.name,
                code: user.code,
                package: user.package,
                packageExpiry: user.packageExpiry,
                remainingTime: getRemainingTime(user.packageExpiry),
                isActive: user.isActive,
                isExpired: user.isExpired,
                lastLogin: user.lastLogin,
                loginCount: user.loginCount,
                deviceId: user.deviceId ? user.deviceId.substring(0, 8) + '...' : null,
                isAutoLoggedOut: user.isAutoLoggedOut,
                autoLogoutReason: user.autoLogoutReason,
                createdAt: user.createdAt,
                updatedAt: user.updatedAt
            }
        });
    } catch (error) {
        console.error('Get user by ID error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch user details'
        });
    }
};

// Update user package
const updateUserPackage = async (req, res) => {
    try {
        const { userId } = req.params;
        const { package: newPackage } = req.body;
        const user = req.targetUser; // Set by canManageUser middleware

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (!['24h', '3d', '7d'].includes(newPackage)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid package type. Must be 24h, 3d, or 7d'
            });
        }

        const oldPackage = user.package;
        const oldExpiry = user.packageExpiry;

        // Update package and expiry
        user.package = newPackage;
        user.packageExpiry = getPackageExpiry(newPackage);
        user.isActive = true; // Reactivate user
        user.isAutoLoggedOut = false;
        user.autoLogoutReason = null;

        await user.save();

        // Log package update
        await ActivityLog.logUserManagement({
            adminId: req.user._id,
            adminModel: req.userRole === 'subadmin' ? 'SubAdmin' : 'MainAdmin',
            adminName: req.user.name,
            adminUsername: req.user.username,
            targetId: user._id,
            targetModel: 'User',
            targetName: user.name,
            targetIdentifier: user.code,
            action: 'user_package_updated',
            description: `Updated user package from ${oldPackage} to ${newPackage}`,
            metadata: {
                oldPackage,
                newPackage,
                oldExpiry,
                newExpiry: user.packageExpiry
            },
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            success: true,
            message: 'User package updated successfully',
            user: {
                id: user._id,
                name: user.name,
                code: user.code,
                package: user.package,
                packageExpiry: user.packageExpiry,
                remainingTime: getRemainingTime(user.packageExpiry),
                isActive: user.isActive,
                isExpired: user.isExpired
            }
        });
    } catch (error) {
        console.error('Update user package error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user package'
        });
    }
};

// Delete user
const deleteUser = async (req, res) => {
    try {
        const { userId } = req.params;
        const user = req.targetUser; // Set by canManageUser middleware

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Store user info for logging
        const userInfo = {
            id: user._id,
            name: user.name,
            code: user.code,
            package: user.package
        };

        // Delete user
        await User.findByIdAndDelete(userId);

        // Update sub-admin stats
        await SubAdmin.findByIdAndUpdate(user.subAdmin, {
            $inc: {
                activeUsers: -1
            }
        });

        // Log user deletion
        await ActivityLog.logUserManagement({
            adminId: req.user._id,
            adminModel: req.userRole === 'subadmin' ? 'SubAdmin' : 'MainAdmin',
            adminName: req.user.name,
            adminUsername: req.user.username,
            targetId: userInfo.id,
            targetModel: 'User',
            targetName: userInfo.name,
            targetIdentifier: userInfo.code,
            action: 'user_deleted',
            description: `Deleted user ${userInfo.name} (${userInfo.code})`,
            metadata: {
                deletedUser: userInfo
            },
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            success: true,
            message: 'User deleted successfully',
            deletedUser: userInfo
        });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete user'
        });
    }
};

// Search users by name or code
const searchUsers = async (req, res) => {
    try {
        const { q: query } = req.query;
        const subAdminId = req.user._id;

        if (!query || query.length < 2) {
            return res.status(400).json({
                success: false,
                message: 'Search query must be at least 2 characters long'
            });
        }

        // Log search activity
        await ActivityLog.logUserManagement({
            adminId: subAdminId,
            adminModel: 'SubAdmin',
            adminName: req.user.name,
            adminUsername: req.user.username,
            action: 'user_searched',
            description: `Searched users with query: ${query}`,
            metadata: {
                searchQuery: query
            },
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        const users = await User.find({
            subAdmin: subAdminId,
            $or: [
                { name: { $regex: query, $options: 'i' } },
                { code: { $regex: query.toUpperCase(), $options: 'i' } }
            ]
        })
        .limit(20)
        .select('name code package packageExpiry isActive createdAt')
        .sort({ createdAt: -1 });

        const formattedUsers = users.map(user => ({
            id: user._id,
            name: user.name,
            code: user.code,
            package: user.package,
            remainingTime: getRemainingTime(user.packageExpiry),
            isActive: user.isActive,
            isExpired: user.isExpired,
            createdAt: user.createdAt
        }));

        res.json({
            success: true,
            query,
            results: formattedUsers,
            count: formattedUsers.length
        });
    } catch (error) {
        console.error('Search users error:', error);
        res.status(500).json({
            success: false,
            message: 'Search failed'
        });
    }
};

// Get user dashboard stats (for current logged-in user)
const getUserDashboard = async (req, res) => {
    try {
        const user = req.user; // Current logged-in user

        // Populate sub-admin info
        await user.populate('subAdmin', 'name username email phone');

        const dashboardData = {
            user: {
                id: user._id,
                name: user.name,
                code: user.code,
                package: user.package,
                packageExpiry: user.packageExpiry,
                remainingTime: getRemainingTime(user.packageExpiry),
                isActive: user.isActive,
                isExpired: user.isExpired,
                lastLogin: user.lastLogin,
                loginCount: user.loginCount,
                createdAt: user.createdAt
            },
            subAdmin: {
                name: user.subAdmin.name,
                username: user.subAdmin.username,
                email: user.subAdmin.email,
                phone: user.subAdmin.phone
            },
            status: {
                canAccess: user.isActive && !user.isExpired,
                timeRemaining: getRemainingTime(user.packageExpiry),
                packageStatus: user.isExpired ? 'expired' : 'active'
            }
        };

        res.json({
            success: true,
            dashboard: dashboardData
        });
    } catch (error) {
        console.error('Get user dashboard error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load dashboard'
        });
    }
};

module.exports = {
    createUser,
    getMyUsers,
    getUserById,
    updateUserPackage,
    deleteUser,
    searchUsers,
    getUserDashboard
};