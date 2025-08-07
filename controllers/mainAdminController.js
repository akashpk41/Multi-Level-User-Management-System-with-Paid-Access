// Update package prices (MainAdmin only)
const updatePackagePrices = async (req, res) => {
    try {
        const { prices } = req.body; // { "7d": 2500, "15d": 4500, "30d": 8000 }
        const mainAdmin = req.user;

        if (!prices || typeof prices !== 'object') {
            return res.status(400).json({
                success: false,
                message: 'Package prices object is required'
            });
        }

        const validPackages = ['7d', '15d', '30d'];

        // Get old prices for logging
        const oldPrices = { ...mainAdmin.packagePrices } || {
            '7d': 2500,
            '15d': 4500,
            '30d': 8000
        };

        // Initialize packagePrices if not exists
        if (!mainAdmin.packagePrices) {
            mainAdmin.packagePrices = {
                '7d': 2500,
                '15d': 4500,
                '30d': 8000
            };
        }

        // Validate and update prices
        for (const [packageType, price] of Object.entries(prices)) {
            if (!validPackages.includes(packageType)) {
                return res.status(400).json({
                    success: false,
                    message: `Invalid package type: ${packageType}. Must be 7d, 15d, or 30d`
                });
            }

            if (typeof price !== 'number' || price < 100 || price > 50000) {
                return res.status(400).json({
                    success: false,
                    message: `Invalid price for ${packageType}. Must be between 100 and 50000`
                });
            }

            mainAdmin.packagePrices[packageType] = price;
        }

        // Mark as modified and save
        mainAdmin.markModified('packagePrices');
        await mainAdmin.save();

        // Log price update
        await ActivityLog.logUserManagement({
            adminId: mainAdmin._id,
            adminModel: 'MainAdmin',
            adminName: mainAdmin.name,
            adminUsername: mainAdmin.username,
            action: 'package_prices_updated',
            description: 'Updated package pricing',
            metadata: {
                oldPrices,
                newPrices: mainAdmin.packagePrices,
                updatedPackages: Object.keys(prices)
            },
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            success: true,
            message: 'Package prices updated successfully',
            packagePrices: mainAdmin.packagePrices
        });
    } catch (error) {
        console.error('Update package prices error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update package prices'
        });
    }
};

// Get sales analytics (MainAdmin only)
const getSalesAnalytics = async (req, res) => {
    try {
        const { period = '30d', startDate, endDate } = req.query;

        let dateFilter = {};
        const now = new Date();

        // Set date range based on period or custom dates
        if (startDate && endDate) {
            dateFilter = {
                $gte: new Date(startDate),
                $lte: new Date(endDate)
            };
        } else {
            switch (period) {
                case '7d':
                    dateFilter.$gte = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                    break;
                case '30d':
                    dateFilter.$gte = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                    break;
                case '90d':
                    dateFilter.$gte = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
                    break;
                default:
                    dateFilter.$gte = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
            }
        }

        // Aggregate sales data
        const salesAnalytics = await SubAdmin.aggregate([
            {
                $unwind: '$salesHistory'
            },
            {
                $match: {
                    'salesHistory.date': dateFilter
                }
            },
            {
                $group: {
                    _id: {
                        year: { $year: '$salesHistory.date' },
                        month: { $month: '$salesHistory.date' },
                        day: { $dayOfMonth: '$salesHistory.date' },
                        package: '$salesHistory.package'
                    },
                    totalAmount: { $sum: '$salesHistory.amount' },
                    count: { $sum: 1 }
                }
            },
            {
                $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 }
            }
        ]);

        // Top performing sub-admins
        const topSubAdmins = await SubAdmin.aggregate([
            {
                $match: {
                    totalSales: { $gt: 0 }
                }
            },
            {
                $project: {
                    username: 1,
                    name: 1,
                    totalSales: 1,
                    package: 1,
                    packagePrice: 1,
                    isActive: 1,
                    totalUsersAdded: 1
                }
            },
            {
                $sort: { totalSales: -1 }
            },
            {
                $limit: 10
            }
        ]);

        // Package-wise sales summary
        const packageSummary = await SubAdmin.aggregate([
            {
                $unwind: '$salesHistory'
            },
            {
                $match: {
                    'salesHistory.date': dateFilter
                }
            },
            {
                $group: {
                    _id: '$salesHistory.package',
                    totalAmount: { $sum: '$salesHistory.amount' },
                    count: { $sum: 1 },
                    avgAmount: { $avg: '$salesHistory.amount' }
                }
            }
        ]);

        // Overall totals
        const totalSales = await SubAdmin.aggregate([
            {
                $group: {
                    _id: null,
                    totalRevenue: { $sum: '$totalSales' },
                    totalSubAdmins: { $sum: 1 },
                    activeSubAdmins: {
                        $sum: {
                            $cond: [
                                {
                                    $and: [
                                        { $eq: ['$isActive', true] },
                                        { $eq: ['$isPaid', true] },
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

        res.json({
            success: true,
            analytics: {
                period,
                dateRange: { startDate: dateFilter.$gte, endDate: dateFilter.$lte || now },
                salesByDay: salesAnalytics,
                topSubAdmins,
                packageSummary,
                totals: totalSales[0] || { totalRevenue: 0, totalSubAdmins: 0, activeSubAdmins: 0 }
            }
        });
    } catch (error) {
        console.error('Get sales analytics error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch sales analytics'
        });
    }
};

// Get package prices (MainAdmin only)
const getPackagePrices = async (req, res) => {
    try {
        const mainAdmin = req.user;

        // Ensure packagePrices exists
        if (!mainAdmin.packagePrices) {
            mainAdmin.packagePrices = {
                '7d': 2500,
                '15d': 4500,
                '30d': 8000
            };
            await mainAdmin.save();
        }

        res.json({
            success: true,
            packagePrices: mainAdmin.packagePrices,
            lastUpdated: mainAdmin.updatedAt
        });
    } catch (error) {
        console.error('Get package prices error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch package prices'
        });
    }
};const { MainAdmin, SubAdmin, User, ActivityLog } = require('../models');
const { getRemainingTime, formatDate, getStartOfDay, getEndOfDay, getStartOfWeek, getEndOfWeek, getStartOfMonth, getEndOfMonth } = require('../utils/dateUtil');

// Get MainAdmin dashboard with system overview
const getMainAdminDashboard = async (req, res) => {
    try {
        const mainAdmin = req.user;

        // Update stats before showing dashboard
        await mainAdmin.updateStats();

        // Get system-wide statistics with sales data
        const [systemStats, salesData] = await Promise.all([
            // Basic counts
            Promise.all([
                SubAdmin.countDocuments(),
                User.countDocuments(),
                SubAdmin.countDocuments({ isActive: true, isPaid: true, packageExpiry: { $gt: new Date() } }),
                User.countDocuments({ isActive: true, packageExpiry: { $gt: new Date() } }),
                SubAdmin.countDocuments({ packageExpiry: { $lte: new Date() } }),
                User.countDocuments({ packageExpiry: { $lte: new Date() } }),
                SubAdmin.countDocuments({ createdAt: { $gte: getStartOfDay(), $lte: getEndOfDay() } }),
                User.countDocuments({ createdAt: { $gte: getStartOfDay(), $lte: getEndOfDay() } })
            ]),

            // Sales data
            SubAdmin.getTotalSales()
        ]);

        // Package distribution
        const packageStats = await User.aggregate([
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

        // Recent activities
        const recentActivities = await ActivityLog.find({
            severity: { $in: ['medium', 'high', 'critical'] }
        })
        .sort({ createdAt: -1 })
        .limit(10)
        .populate('user.id', 'name username code');

        // Top performing sub-admins
        const topSubAdmins = await SubAdmin.aggregate([
            {
                $lookup: {
                    from: 'users',
                    localField: '_id',
                    foreignField: 'subAdmin',
                    as: 'users'
                }
            },
            {
                $project: {
                    name: 1,
                    username: 1,
                    isActive: 1,
                    isPaid: 1,
                    totalUsers: { $size: '$users' },
                    activeUsers: {
                        $size: {
                            $filter: {
                                input: '$users',
                                cond: {
                                    $and: [
                                        { $eq: ['$$this.isActive', true] },
                                        { $gt: ['$$this.packageExpiry', new Date()] }
                                    ]
                                }
                            }
                        }
                    }
                }
            },
            { $sort: { totalUsers: -1 } },
            { $limit: 5 }
        ]);

        const dashboardData = {
            mainAdmin: {
                id: mainAdmin._id,
                name: mainAdmin.name,
                username: mainAdmin.username,
                email: mainAdmin.email,
                crashValue: mainAdmin.crashValue,
                maxDevices: mainAdmin.maxDevices,
                devicesCount: mainAdmin.devices.length,
                lastLogin: mainAdmin.lastLogin,
                loginCount: mainAdmin.loginCount
            },
            systemStats: {
                subAdmins: {
                    total: systemStats[0][0],
                    active: systemStats[0][2],
                    expired: systemStats[0][4],
                    todayRegistrations: systemStats[0][6]
                },
                users: {
                    total: systemStats[0][1],
                    active: systemStats[0][3],
                    expired: systemStats[0][5],
                    todayRegistrations: systemStats[0][7]
                },
                sales: {
                    totalSales: salesData.totalSales,
                    totalSubAdmins: salesData.totalSubAdmins,
                    activeSubAdmins: salesData.activeSubAdmins
                }
            },
            packageStats: packageStats,
            recentActivities: recentActivities.map(activity => ({
                id: activity._id,
                action: activity.action,
                description: activity.description,
                user: activity.user,
                severity: activity.severity,
                createdAt: activity.createdAt,
                formattedTime: activity.formattedTime
            })),
            topSubAdmins: topSubAdmins
        };

        res.json({
            success: true,
            dashboard: dashboardData
        });
    } catch (error) {
        console.error('Get main admin dashboard error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load dashboard'
        });
    }
};

// Get system analytics with charts data
const getSystemAnalytics = async (req, res) => {
    try {
        const { period = '7d' } = req.query;

        let startDate, endDate;
        const now = new Date();

        switch (period) {
            case '24h':
                startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
                endDate = now;
                break;
            case '7d':
                startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                endDate = now;
                break;
            case '30d':
                startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                endDate = now;
                break;
            case 'week':
                startDate = getStartOfWeek();
                endDate = getEndOfWeek();
                break;
            case 'month':
                startDate = getStartOfMonth();
                endDate = getEndOfMonth();
                break;
            default:
                startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                endDate = now;
        }

        // User registrations over time
        const userRegistrations = await User.aggregate([
            {
                $match: {
                    createdAt: { $gte: startDate, $lte: endDate }
                }
            },
            {
                $group: {
                    _id: {
                        year: { $year: '$createdAt' },
                        month: { $month: '$createdAt' },
                        day: { $dayOfMonth: '$createdAt' }
                    },
                    count: { $sum: 1 }
                }
            },
            { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 } }
        ]);

        // Sub-admin registrations over time
        const subAdminRegistrations = await SubAdmin.aggregate([
            {
                $match: {
                    createdAt: { $gte: startDate, $lte: endDate }
                }
            },
            {
                $group: {
                    _id: {
                        year: { $year: '$createdAt' },
                        month: { $month: '$createdAt' },
                        day: { $dayOfMonth: '$createdAt' }
                    },
                    count: { $sum: 1 }
                }
            },
            { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 } }
        ]);

        // Login activities over time
        const loginActivities = await ActivityLog.aggregate([
            {
                $match: {
                    action: 'login',
                    createdAt: { $gte: startDate, $lte: endDate }
                }
            },
            {
                $group: {
                    _id: {
                        year: { $year: '$createdAt' },
                        month: { $month: '$createdAt' },
                        day: { $dayOfMonth: '$createdAt' },
                        role: '$user.model'
                    },
                    count: { $sum: 1 }
                }
            },
            { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 } }
        ]);

        // Package distribution pie chart
        const packageDistribution = await User.aggregate([
            {
                $group: {
                    _id: '$package',
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

        // Revenue simulation (based on active sub-admins)
        const revenueData = await SubAdmin.aggregate([
            {
                $match: {
                    isPaid: true,
                    paymentExpiry: { $gt: new Date() }
                }
            },
            {
                $group: {
                    _id: {
                        year: { $year: '$paymentExpiry' },
                        month: { $month: '$paymentExpiry' }
                    },
                    count: { $sum: 1 }
                }
            }
        ]);

        // Security events
        const securityEvents = await ActivityLog.aggregate([
            {
                $match: {
                    severity: { $in: ['high', 'critical'] },
                    createdAt: { $gte: startDate, $lte: endDate }
                }
            },
            {
                $group: {
                    _id: '$action',
                    count: { $sum: 1 }
                }
            },
            { $sort: { count: -1 } }
        ]);

        // Log analytics view
        await ActivityLog.logAuth({
            userId: req.user._id,
            userModel: 'MainAdmin',
            userName: req.user.name,
            username: req.user.username,
            action: 'analytics_viewed',
            description: `Viewed system analytics for period: ${period}`,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            deviceId: req.deviceId,
            status: 'success',
            severity: 'low'
        });

        res.json({
            success: true,
            analytics: {
                period,
                dateRange: { startDate, endDate },
                userRegistrations,
                subAdminRegistrations,
                loginActivities,
                packageDistribution,
                revenueData,
                securityEvents
            }
        });
    } catch (error) {
        console.error('Get system analytics error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load analytics'
        });
    }
};

// Update crash value
const updateCrashValue = async (req, res) => {
    try {
        const { crashValue } = req.body;
        const mainAdmin = req.user;

        if (!crashValue || typeof crashValue !== 'string') {
            return res.status(400).json({
                success: false,
                message: 'Valid crash value string is required'
            });
        }

        if (crashValue.trim().length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Crash value cannot be empty'
            });
        }

        const oldCrashValue = mainAdmin.crashValue;

        // Update crash value
        mainAdmin.crashValue = crashValue.trim();
        await mainAdmin.save();

        // Log crash value update
        await ActivityLog.logUserManagement({
            adminId: mainAdmin._id,
            adminModel: 'MainAdmin',
            adminName: mainAdmin.name,
            adminUsername: mainAdmin.username,
            action: 'crash_value_updated',
            description: `Updated crash value script`,
            metadata: {
                oldValueLength: oldCrashValue ? oldCrashValue.length : 0,
                newValueLength: crashValue.length,
                timestamp: new Date()
            },
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            success: true,
            message: 'Crash value updated successfully',
            crashValue: {
                length: mainAdmin.crashValue.length,
                preview: mainAdmin.crashValue.substring(0, 50) + '...',
                updated: true
            }
        });
    } catch (error) {
        console.error('Update crash value error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update crash value'
        });
    }
};

// Get all system logs with filters
const getSystemLogs = async (req, res) => {
    try {
        const {
            page = 1,
            limit = 50,
            action = '',
            severity = '',
            userModel = '',
            startDate = '',
            endDate = '',
            search = ''
        } = req.query;

        // Build query
        let query = {};

        if (action) {
            query.action = action;
        }

        if (severity) {
            query.severity = severity;
        }

        if (userModel) {
            query['user.model'] = userModel;
        }

        // Date range filter
        if (startDate || endDate) {
            query.createdAt = {};
            if (startDate) query.createdAt.$gte = new Date(startDate);
            if (endDate) query.createdAt.$lte = new Date(endDate);
        }

        // Search in description or user name
        if (search) {
            query.$or = [
                { description: { $regex: search, $options: 'i' } },
                { 'user.name': { $regex: search, $options: 'i' } },
                { 'user.username': { $regex: search, $options: 'i' } }
            ];
        }

        // Execute query with pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);

        const [logs, totalCount] = await Promise.all([
            ActivityLog.find(query)
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(parseInt(limit))
                .populate('user.id', 'name username code')
                .populate('target.id', 'name username code'),
            ActivityLog.countDocuments(query)
        ]);

        // Get filter options for frontend
        const filterOptions = await Promise.all([
            ActivityLog.distinct('action'),
            ActivityLog.distinct('severity'),
            ActivityLog.distinct('user.model')
        ]);

        // Log viewing system logs
        await ActivityLog.logAuth({
            userId: req.user._id,
            userModel: 'MainAdmin',
            userName: req.user.name,
            username: req.user.username,
            action: 'logs_viewed',
            description: `Viewed system logs with filters: ${JSON.stringify({ action, severity, userModel })}`,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            deviceId: req.deviceId,
            status: 'success',
            severity: 'low'
        });

        res.json({
            success: true,
            logs: logs,
            pagination: {
                currentPage: parseInt(page),
                totalPages: Math.ceil(totalCount / parseInt(limit)),
                totalCount,
                hasNext: skip + logs.length < totalCount,
                hasPrev: parseInt(page) > 1
            },
            filterOptions: {
                actions: filterOptions[0],
                severities: filterOptions[1],
                userModels: filterOptions[2]
            },
            appliedFilters: {
                action,
                severity,
                userModel,
                startDate,
                endDate,
                search
            }
        });
    } catch (error) {
        console.error('Get system logs error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch system logs'
        });
    }
};

// Get security events (high priority logs)
const getSecurityEvents = async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;

        const skip = (parseInt(page) - 1) * parseInt(limit);

        const [events, totalCount] = await Promise.all([
            ActivityLog.find({
                severity: { $in: ['high', 'critical'] }
            })
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit))
            .populate('user.id', 'name username code'),

            ActivityLog.countDocuments({
                severity: { $in: ['high', 'critical'] }
            })
        ]);

        // Group events by type for summary
        const eventSummary = await ActivityLog.aggregate([
            {
                $match: {
                    severity: { $in: ['high', 'critical'] },
                    createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Last 24 hours
                }
            },
            {
                $group: {
                    _id: '$action',
                    count: { $sum: 1 },
                    severity: { $first: '$severity' }
                }
            },
            { $sort: { count: -1 } }
        ]);

        res.json({
            success: true,
            events,
            eventSummary,
            pagination: {
                currentPage: parseInt(page),
                totalPages: Math.ceil(totalCount / parseInt(limit)),
                totalCount,
                hasNext: skip + events.length < totalCount,
                hasPrev: parseInt(page) > 1
            }
        });
    } catch (error) {
        console.error('Get security events error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch security events'
        });
    }
};

// Get system health status
const getSystemHealth = async (req, res) => {
    try {
        const now = new Date();
        const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        // Check various system metrics
        const [
            totalUsers,
            activeUsers,
            totalSubAdmins,
            activeSubAdmins,
            failedLogins,
            securityEvents,
            recentErrors
        ] = await Promise.all([
            User.countDocuments(),
            User.countDocuments({ isActive: true, packageExpiry: { $gt: now } }),
            SubAdmin.countDocuments(),
            SubAdmin.countDocuments({ isActive: true, isPaid: true, paymentExpiry: { $gt: now } }),
            ActivityLog.countDocuments({
                action: 'failed_login',
                createdAt: { $gte: last24Hours }
            }),
            ActivityLog.countDocuments({
                severity: { $in: ['high', 'critical'] },
                createdAt: { $gte: last24Hours }
            }),
            ActivityLog.countDocuments({
                status: 'failed',
                createdAt: { $gte: last24Hours }
            })
        ]);

        // Calculate health scores
        const userHealthScore = totalUsers > 0 ? Math.round((activeUsers / totalUsers) * 100) : 100;
        const subAdminHealthScore = totalSubAdmins > 0 ? Math.round((activeSubAdmins / totalSubAdmins) * 100) : 100;

        // Determine overall system health
        let systemStatus = 'healthy';
        let statusMessage = 'All systems operational';

        if (failedLogins > 50 || securityEvents > 10 || recentErrors > 20) {
            systemStatus = 'warning';
            statusMessage = 'Some issues detected';
        }

        if (failedLogins > 100 || securityEvents > 20 || recentErrors > 50) {
            systemStatus = 'critical';
            statusMessage = 'Critical issues require attention';
        }

        const healthData = {
            status: systemStatus,
            message: statusMessage,
            timestamp: now,
            metrics: {
                users: {
                    total: totalUsers,
                    active: activeUsers,
                    healthScore: userHealthScore
                },
                subAdmins: {
                    total: totalSubAdmins,
                    active: activeSubAdmins,
                    healthScore: subAdminHealthScore
                },
                security: {
                    failedLogins,
                    securityEvents,
                    recentErrors
                }
            },
            uptime: process.uptime(),
            memory: process.memoryUsage()
        };

        res.json({
            success: true,
            health: healthData
        });
    } catch (error) {
        console.error('Get system health error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to check system health',
            health: {
                status: 'error',
                message: 'Health check failed',
                timestamp: new Date()
            }
        });
    }
};

// Force logout user/subadmin (emergency action)
const forceLogoutUser = async (req, res) => {
    try {
        const { userId, userRole } = req.body;

        if (!userId || !userRole) {
            return res.status(400).json({
                success: false,
                message: 'User ID and role are required'
            });
        }

        if (!['user', 'subadmin'].includes(userRole)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid user role. Must be user or subadmin'
            });
        }

        let user;
        let Model = userRole === 'user' ? User : SubAdmin;

        user = await Model.findById(userId);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: `${userRole} not found`
            });
        }

        // Force logout
        user.deviceId = null;
        user.refreshToken = null;
        user.isAutoLoggedOut = true;
        user.autoLogoutReason = 'main_admin_action';

        await user.save();

        // If sub-admin, also logout their users
        if (userRole === 'subadmin') {
            await User.updateMany(
                { subAdmin: userId },
                {
                    deviceId: null,
                    refreshToken: null,
                    isActive: false,
                    isAutoLoggedOut: true,
                    autoLogoutReason: 'sub_admin_logout'
                }
            );
        }

        // Log force logout action
        await ActivityLog.logUserManagement({
            adminId: req.user._id,
            adminModel: 'MainAdmin',
            adminName: req.user.name,
            adminUsername: req.user.username,
            targetId: userId,
            targetModel: userRole === 'user' ? 'User' : 'SubAdmin',
            targetName: user.name,
            targetIdentifier: user.username || user.code,
            action: 'force_logout',
            description: `Force logged out ${userRole}: ${user.name}`,
            metadata: {
                reason: 'main_admin_action',
                userRole
            },
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            success: true,
            message: `${userRole} force logged out successfully`,
            user: {
                id: user._id,
                name: user.name,
                identifier: user.username || user.code
            }
        });
    } catch (error) {
        console.error('Force logout user error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to force logout user'
        });
    }
};

module.exports = {
    getMainAdminDashboard,
    getSystemAnalytics,
    updateCrashValue,
    getSystemLogs,
    getSecurityEvents,
    getSystemHealth,
    forceLogoutUser,
    updatePackagePrices,
    getSalesAnalytics,
    getPackagePrices
};