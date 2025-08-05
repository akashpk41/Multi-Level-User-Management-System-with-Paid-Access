const { SubAdmin, User, MainAdmin, ActivityLog } = require('../models');
const { generateTempPassword } = require('../utils/generateTokens');
const { getPaymentExpiry, getRemainingTime, formatDate } = require('../utils/dateUtil');

// Create new SubAdmin (MainAdmin only)
const createSubAdmin = async (req, res) => {
    try {
        const { username, name, email, phone, password } = req.body;
        const mainAdminId = req.user._id;

        // Validation
        if (!username || !name) {
            return res.status(400).json({
                success: false,
                message: 'Username and name are required'
            });
        }

        // Generate password if not provided
        const subAdminPassword = password || generateTempPassword();

        // Create sub-admin
        const subAdmin = new SubAdmin({
            username: username.toLowerCase().trim(),
            name: name.trim(),
            email: email ? email.toLowerCase().trim() : undefined,
            phone: phone ? phone.trim() : undefined,
            password: subAdminPassword,
            createdBy: mainAdminId,
            isActive: false, // Main admin will activate manually
            isPaid: false
        });

        await subAdmin.save();

        // Update main admin stats
        await MainAdmin.findByIdAndUpdate(mainAdminId, {
            $inc: { totalSubAdmins: 1 }
        });

        // Log sub-admin creation
        await ActivityLog.logUserManagement({
            adminId: mainAdminId,
            adminModel: 'MainAdmin',
            adminName: req.user.name,
            adminUsername: req.user.username,
            targetId: subAdmin._id,
            targetModel: 'SubAdmin',
            targetName: subAdmin.name,
            targetIdentifier: subAdmin.username,
            action: 'subadmin_created',
            description: `Created sub-admin ${subAdmin.name} (${subAdmin.username})`,
            metadata: {
                email: subAdmin.email,
                phone: subAdmin.phone,
                generatedPassword: !password // Whether password was auto-generated
            },
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.status(201).json({
            success: true,
            message: 'Sub-admin created successfully',
            subAdmin: {
                id: subAdmin._id,
                username: subAdmin.username,
                name: subAdmin.name,
                email: subAdmin.email,
                phone: subAdmin.phone,
                isActive: subAdmin.isActive,
                isPaid: subAdmin.isPaid,
                createdAt: subAdmin.createdAt
            },
            // Only send password if it was auto-generated
            ...(!password && { temporaryPassword: subAdminPassword })
        });
    } catch (error) {
        console.error('Create sub-admin error:', error);

        if (error.code === 11000) {
            const field = Object.keys(error.keyValue)[0];
            return res.status(400).json({
                success: false,
                message: `${field} already exists`
            });
        }

        res.status(500).json({
            success: false,
            message: 'Failed to create sub-admin'
        });
    }
};

// Get all SubAdmins (MainAdmin only)
const getAllSubAdmins = async (req, res) => {
    try {
        const {
            page = 1,
            limit = 10,
            search = '',
            status = 'all',
            paymentStatus = 'all',
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;

        // Build query
        let query = {};

        // Search by name or username
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { username: { $regex: search, $options: 'i' } }
            ];
        }

        // Filter by status
        if (status === 'active') {
            query.isActive = true;
        } else if (status === 'inactive') {
            query.isActive = false;
        }

        // Filter by payment status
        if (paymentStatus === 'paid') {
            query.isPaid = true;
            query.paymentExpiry = { $gt: new Date() };
        } else if (paymentStatus === 'unpaid') {
            query.isPaid = false;
        } else if (paymentStatus === 'expired') {
            query.paymentExpiry = { $lte: new Date() };
        }

        // Sort options
        const sortOptions = {};
        sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;

        // Execute query with pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);

        const [subAdmins, totalCount] = await Promise.all([
            SubAdmin.find(query)
                .sort(sortOptions)
                .skip(skip)
                .limit(parseInt(limit))
                .select('-password -refreshToken -__v')
                .populate('createdBy', 'name username'),
            SubAdmin.countDocuments(query)
        ]);

        // Format sub-admins data with user counts
        const formattedSubAdmins = await Promise.all(
            subAdmins.map(async (subAdmin) => {
                const userCounts = await User.aggregate([
                    { $match: { subAdmin: subAdmin._id } },
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
                            }
                        }
                    }
                ]);

                const counts = userCounts[0] || { total: 0, active: 0 };

                return {
                    id: subAdmin._id,
                    username: subAdmin.username,
                    name: subAdmin.name,
                    email: subAdmin.email,
                    phone: subAdmin.phone,
                    isActive: subAdmin.isActive,
                    isPaid: subAdmin.isPaid,
                    paymentExpiry: subAdmin.paymentExpiry,
                    remainingPaymentTime: getRemainingTime(subAdmin.paymentExpiry),
                    canAccess: subAdmin.canAccess,
                    lastLogin: subAdmin.lastLogin,
                    loginCount: subAdmin.loginCount,
                    totalUsers: counts.total,
                    activeUsers: counts.active,
                    createdBy: subAdmin.createdBy,
                    createdAt: subAdmin.createdAt,
                    updatedAt: subAdmin.updatedAt
                };
            })
        );

        // Get stats
        const stats = await SubAdmin.aggregate([
            {
                $group: {
                    _id: null,
                    total: { $sum: 1 },
                    active: {
                        $sum: {
                            $cond: [{ $eq: ['$isActive', true] }, 1, 0]
                        }
                    },
                    paid: {
                        $sum: {
                            $cond: [
                                {
                                    $and: [
                                        { $eq: ['$isPaid', true] },
                                        { $gt: ['$paymentExpiry', new Date()] }
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
                                { $lte: ['$paymentExpiry', new Date()] },
                                1,
                                0
                            ]
                        }
                    }
                }
            }
        ]);

        const subAdminStats = stats[0] || { total: 0, active: 0, paid: 0, expired: 0 };

        res.json({
            success: true,
            subAdmins: formattedSubAdmins,
            pagination: {
                currentPage: parseInt(page),
                totalPages: Math.ceil(totalCount / parseInt(limit)),
                totalCount,
                hasNext: skip + subAdmins.length < totalCount,
                hasPrev: parseInt(page) > 1
            },
            stats: subAdminStats,
            filters: {
                search,
                status,
                paymentStatus,
                sortBy,
                sortOrder
            }
        });
    } catch (error) {
        console.error('Get all sub-admins error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch sub-admins'
        });
    }
};

// Get single SubAdmin details
const getSubAdminById = async (req, res) => {
    try {
        const { subAdminId } = req.params;
        const subAdmin = req.targetSubAdmin; // Set by canManageSubAdmin middleware

        if (!subAdmin) {
            return res.status(404).json({
                success: false,
                message: 'Sub-admin not found'
            });
        }

        // Get user statistics
        const userStats = await User.aggregate([
            { $match: { subAdmin: subAdmin._id } },
            {
                $group: {
                    _id: '$package',
                    count: { $sum: 1 },
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
                    }
                }
            }
        ]);

        const totalStats = await User.aggregate([
            { $match: { subAdmin: subAdmin._id } },
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
                    }
                }
            }
        ]);

        const stats = totalStats[0] || { total: 0, active: 0, expired: 0 };

        // Log view activity
        await ActivityLog.logUserManagement({
            adminId: req.user._id,
            adminModel: 'MainAdmin',
            adminName: req.user.name,
            adminUsername: req.user.username,
            targetId: subAdmin._id,
            targetModel: 'SubAdmin',
            targetName: subAdmin.name,
            targetIdentifier: subAdmin.username,
            action: 'subadmin_viewed',
            description: `Viewed sub-admin details: ${subAdmin.name} (${subAdmin.username})`,
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            success: true,
            subAdmin: {
                id: subAdmin._id,
                username: subAdmin.username,
                name: subAdmin.name,
                email: subAdmin.email,
                phone: subAdmin.phone,
                isActive: subAdmin.isActive,
                isPaid: subAdmin.isPaid,
                paymentExpiry: subAdmin.paymentExpiry,
                remainingPaymentTime: getRemainingTime(subAdmin.paymentExpiry),
                canAccess: subAdmin.canAccess,
                lastLogin: subAdmin.lastLogin,
                loginCount: subAdmin.loginCount,
                totalUsersAdded: subAdmin.totalUsersAdded,
                activeUsers: subAdmin.activeUsers,
                createdAt: subAdmin.createdAt,
                updatedAt: subAdmin.updatedAt
            },
            userStats: {
                total: stats.total,
                active: stats.active,
                expired: stats.expired,
                byPackage: userStats
            }
        });
    } catch (error) {
        console.error('Get sub-admin by ID error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch sub-admin details'
        });
    }
};

// Update SubAdmin payment (MainAdmin only)
const updateSubAdminPayment = async (req, res) => {
    try {
        const { subAdminId } = req.params;
        const { days = 30, activate = true } = req.body;
        const subAdmin = req.targetSubAdmin; // Set by canManageSubAdmin middleware

        if (!subAdmin) {
            return res.status(404).json({
                success: false,
                message: 'Sub-admin not found'
            });
        }

        if (days < 1 || days > 365) {
            return res.status(400).json({
                success: false,
                message: 'Payment days must be between 1 and 365'
            });
        }

        const oldPaymentExpiry = subAdmin.paymentExpiry;
        const oldStatus = { isActive: subAdmin.isActive, isPaid: subAdmin.isPaid };

        // Update payment
        subAdmin.setPaymentExpiry(days);
        if (activate) {
            subAdmin.isActive = true;
        }

        await subAdmin.save();

        // Log payment update
        await ActivityLog.logUserManagement({
            adminId: req.user._id,
            adminModel: 'MainAdmin',
            adminName: req.user.name,
            adminUsername: req.user.username,
            targetId: subAdmin._id,
            targetModel: 'SubAdmin',
            targetName: subAdmin.name,
            targetIdentifier: subAdmin.username,
            action: 'payment_updated',
            description: `Updated payment for ${days} days${activate ? ' and activated account' : ''}`,
            metadata: {
                oldPaymentExpiry,
                newPaymentExpiry: subAdmin.paymentExpiry,
                days,
                activated: activate,
                oldStatus
            },
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            success: true,
            message: 'Payment updated successfully',
            subAdmin: {
                id: subAdmin._id,
                username: subAdmin.username,
                name: subAdmin.name,
                isActive: subAdmin.isActive,
                isPaid: subAdmin.isPaid,
                paymentExpiry: subAdmin.paymentExpiry,
                remainingPaymentTime: getRemainingTime(subAdmin.paymentExpiry),
                canAccess: subAdmin.canAccess
            }
        });
    } catch (error) {
        console.error('Update sub-admin payment error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update payment'
        });
    }
};

// Activate/Deactivate SubAdmin (MainAdmin only)
const toggleSubAdminStatus = async (req, res) => {
    try {
        const { subAdminId } = req.params;
        const { isActive } = req.body;
        const subAdmin = req.targetSubAdmin; // Set by canManageSubAdmin middleware

        if (!subAdmin) {
            return res.status(404).json({
                success: false,
                message: 'Sub-admin not found'
            });
        }

        if (typeof isActive !== 'boolean') {
            return res.status(400).json({
                success: false,
                message: 'isActive must be a boolean value'
            });
        }

        const oldStatus = subAdmin.isActive;
        subAdmin.isActive = isActive;

        // If deactivating, auto-logout sub-admin and all their users
        if (!isActive) {
            await subAdmin.checkAndAutoLogout();
        }

        await subAdmin.save();

        // Log status change
        await ActivityLog.logUserManagement({
            adminId: req.user._id,
            adminModel: 'MainAdmin',
            adminName: req.user.name,
            adminUsername: req.user.username,
            targetId: subAdmin._id,
            targetModel: 'SubAdmin',
            targetName: subAdmin.name,
            targetIdentifier: subAdmin.username,
            action: isActive ? 'subadmin_activated' : 'subadmin_deactivated',
            description: `${isActive ? 'Activated' : 'Deactivated'} sub-admin account`,
            metadata: {
                oldStatus,
                newStatus: isActive
            },
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            success: true,
            message: `Sub-admin ${isActive ? 'activated' : 'deactivated'} successfully`,
            subAdmin: {
                id: subAdmin._id,
                username: subAdmin.username,
                name: subAdmin.name,
                isActive: subAdmin.isActive,
                canAccess: subAdmin.canAccess
            }
        });
    } catch (error) {
        console.error('Toggle sub-admin status error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update sub-admin status'
        });
    }
};

// Delete SubAdmin (MainAdmin only)
const deleteSubAdmin = async (req, res) => {
    try {
        const { subAdminId } = req.params;
        const subAdmin = req.targetSubAdmin; // Set by canManageSubAdmin middleware

        if (!subAdmin) {
            return res.status(404).json({
                success: false,
                message: 'Sub-admin not found'
            });
        }

        // Store sub-admin info for logging
        const subAdminInfo = {
            id: subAdmin._id,
            username: subAdmin.username,
            name: subAdmin.name,
            email: subAdmin.email
        };

        // Get user count before deletion
        const userCount = await User.countDocuments({ subAdmin: subAdminId });

        // Delete all users under this sub-admin
        await User.deleteMany({ subAdmin: subAdminId });

        // Delete sub-admin
        await SubAdmin.findByIdAndDelete(subAdminId);

        // Update main admin stats
        await MainAdmin.findByIdAndUpdate(req.user._id, {
            $inc: {
                totalSubAdmins: -1,
                totalUsers: -userCount
            }
        });

        // Log sub-admin deletion
        await ActivityLog.logUserManagement({
            adminId: req.user._id,
            adminModel: 'MainAdmin',
            adminName: req.user.name,
            adminUsername: req.user.username,
            targetId: subAdminInfo.id,
            targetModel: 'SubAdmin',
            targetName: subAdminInfo.name,
            targetIdentifier: subAdminInfo.username,
            action: 'subadmin_deleted',
            description: `Deleted sub-admin ${subAdminInfo.name} (${subAdminInfo.username}) and ${userCount} associated users`,
            metadata: {
                deletedSubAdmin: subAdminInfo,
                deletedUsersCount: userCount
            },
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            success: true,
            message: 'Sub-admin and all associated users deleted successfully',
            deletedSubAdmin: subAdminInfo,
            deletedUsersCount: userCount
        });
    } catch (error) {
        console.error('Delete sub-admin error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete sub-admin'
        });
    }
};

// Get SubAdmin dashboard stats (for current logged-in sub-admin)
const getSubAdminDashboard = async (req, res) => {
    try {
        const subAdmin = req.user; // Current logged-in sub-admin

        // Get user statistics
        const userStats = await User.aggregate([
            { $match: { subAdmin: subAdmin._id } },
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

        const packageStats = await User.aggregate([
            { $match: { subAdmin: subAdmin._id } },
            {
                $group: {
                    _id: '$package',
                    count: { $sum: 1 },
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
                    }
                }
            }
        ]);

        const recentUsers = await User.find({ subAdmin: subAdmin._id })
            .sort({ createdAt: -1 })
            .limit(5)
            .select('name code package packageExpiry isActive createdAt');

        const stats = userStats[0] || { total: 0, active: 0, expired: 0, inactive: 0 };

        const dashboardData = {
            subAdmin: {
                id: subAdmin._id,
                name: subAdmin.name,
                username: subAdmin.username,
                email: subAdmin.email,
                phone: subAdmin.phone,
                isActive: subAdmin.isActive,
                isPaid: subAdmin.isPaid,
                paymentExpiry: subAdmin.paymentExpiry,
                remainingPaymentTime: getRemainingTime(subAdmin.paymentExpiry),
                canAccess: subAdmin.canAccess,
                lastLogin: subAdmin.lastLogin,
                loginCount: subAdmin.loginCount
            },
            userStats: stats,
            packageStats: packageStats,
            recentUsers: recentUsers.map(user => ({
                id: user._id,
                name: user.name,
                code: user.code,
                package: user.package,
                remainingTime: getRemainingTime(user.packageExpiry),
                isActive: user.isActive,
                isExpired: user.isExpired,
                createdAt: user.createdAt
            })),
            status: {
                canCreateUsers: subAdmin.canAccess,
                paymentStatus: subAdmin.isPaymentExpired ? 'expired' : 'active',
                accountStatus: subAdmin.isActive ? 'active' : 'inactive'
            }
        };

        res.json({
            success: true,
            dashboard: dashboardData
        });
    } catch (error) {
        console.error('Get sub-admin dashboard error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load dashboard'
        });
    }
};

// Reset SubAdmin password (MainAdmin only)
const resetSubAdminPassword = async (req, res) => {
    try {
        const { subAdminId } = req.params;
        const { newPassword } = req.body;
        const subAdmin = req.targetSubAdmin;

        if (!subAdmin) {
            return res.status(404).json({
                success: false,
                message: 'Sub-admin not found'
            });
        }

        // Generate new password if not provided
        const finalPassword = newPassword || generateTempPassword();

        if (finalPassword.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 6 characters long'
            });
        }

        // Update password
        subAdmin.password = finalPassword;
        await subAdmin.save();

        // Log password reset
        await ActivityLog.logUserManagement({
            adminId: req.user._id,
            adminModel: 'MainAdmin',
            adminName: req.user.name,
            adminUsername: req.user.username,
            targetId: subAdmin._id,
            targetModel: 'SubAdmin',
            targetName: subAdmin.name,
            targetIdentifier: subAdmin.username,
            action: 'password_reset',
            description: `Reset password for sub-admin ${subAdmin.name}`,
            metadata: {
                generatedPassword: !newPassword
            },
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            success: true,
            message: 'Password reset successfully',
            subAdmin: {
                id: subAdmin._id,
                username: subAdmin.username,
                name: subAdmin.name
            },
            // Only send password if it was auto-generated
            ...(!newPassword && { newPassword: finalPassword })
        });
    } catch (error) {
        console.error('Reset sub-admin password error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reset password'
        });
    }
};

module.exports = {
    createSubAdmin,
    getAllSubAdmins,
    getSubAdminById,
    updateSubAdminPayment,
    toggleSubAdminStatus,
    deleteSubAdmin,
    getSubAdminDashboard,
    resetSubAdminPassword
};