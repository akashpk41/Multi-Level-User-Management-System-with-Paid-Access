const mongoose = require('mongoose');

const activityLogSchema = new mongoose.Schema({
    // Who performed the action
    user: {
        id: {
            type: mongoose.Schema.Types.ObjectId,
            required: true,
            refPath: 'user.model'
        },
        model: {
            type: String,
            required: true,
            enum: ['User', 'SubAdmin', 'MainAdmin']
        },
        name: {
            type: String,
            required: true
        },
        username: String, // For SubAdmin and MainAdmin
        code: String // For User
    },

    // Action Details
    action: {
        type: String,
        required: true,
        enum: [
            // Authentication
            'login', 'logout', 'auto_logout', 'device_change_logout',

            // User Management (Sub-Admin actions)
            'user_created', 'user_updated', 'user_deleted', 'user_package_updated',
            'user_searched', 'user_viewed',

            // Sub-Admin Management (Main Admin actions)
            'subadmin_created', 'subadmin_updated', 'subadmin_deleted',
            'subadmin_activated', 'subadmin_deactivated',
            'payment_updated', 'payment_extended',

            // System Actions (Main Admin)
            'crash_value_updated', 'system_settings_updated',
            'logs_viewed', 'analytics_viewed',

            // Security Events
            'failed_login', 'password_changed', 'device_locked',
            'suspicious_activity', 'rate_limit_exceeded'
        ]
    },

    // Action Description
    description: {
        type: String,
        required: true
    },

    // Target (যার উপর action করা হয়েছে)
    target: {
        id: {
            type: mongoose.Schema.Types.ObjectId,
            refPath: 'target.model'
        },
        model: {
            type: String,
            enum: ['User', 'SubAdmin', 'MainAdmin', 'System']
        },
        name: String,
        identifier: String // username or code
    },

    // Request Details
    requestInfo: {
        ip: String,
        userAgent: String,
        deviceId: String,
        method: String, // GET, POST, PUT, DELETE
        endpoint: String,
        statusCode: Number
    },

    // Additional Data
    metadata: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    },

    // Status
    status: {
        type: String,
        enum: ['success', 'failed', 'warning'],
        default: 'success'
    },

    // Security Level
    severity: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical'],
        default: 'low'
    }
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// Virtual for formatted timestamp
activityLogSchema.virtual('formattedTime').get(function() {
    return {
        date: this.createdAt.toLocaleDateString(),
        time: this.createdAt.toLocaleTimeString(),
        relative: getRelativeTime(this.createdAt)
    };
});

// Helper function for relative time
function getRelativeTime(date) {
    const now = new Date();
    const diffInMs = now - date;
    const diffInMinutes = Math.floor(diffInMs / (1000 * 60));
    const diffInHours = Math.floor(diffInMinutes / 60);
    const diffInDays = Math.floor(diffInHours / 24);

    if (diffInMinutes < 1) return 'Just now';
    if (diffInMinutes < 60) return `${diffInMinutes} minutes ago`;
    if (diffInHours < 24) return `${diffInHours} hours ago`;
    if (diffInDays < 7) return `${diffInDays} days ago`;
    return date.toLocaleDateString();
}

// Static method to log activity
activityLogSchema.statics.logActivity = async function(logData) {
    try {
        const log = new this(logData);
        await log.save();
        return log;
    } catch (error) {
        console.error('Error logging activity:', error);
        // Don't throw error to prevent breaking main functionality
    }
};

// Static method to log authentication events
activityLogSchema.statics.logAuth = async function({
    userId, userModel, userName, username, code, action, description,
    ip, userAgent, deviceId, status = 'success', severity = 'low'
}) {
    return this.logActivity({
        user: {
            id: userId,
            model: userModel,
            name: userName,
            username: username,
            code: code
        },
        action,
        description,
        requestInfo: {
            ip,
            userAgent,
            deviceId
        },
        status,
        severity
    });
};

// Static method to log user management events
activityLogSchema.statics.logUserManagement = async function({
    adminId, adminModel, adminName, adminUsername,
    targetId, targetModel, targetName, targetIdentifier,
    action, description, metadata = {}, ip, userAgent
}) {
    return this.logActivity({
        user: {
            id: adminId,
            model: adminModel,
            name: adminName,
            username: adminUsername
        },
        target: {
            id: targetId,
            model: targetModel,
            name: targetName,
            identifier: targetIdentifier
        },
        action,
        description,
        metadata,
        requestInfo: {
            ip,
            userAgent
        },
        severity: 'medium'
    });
};

// Static method to get recent activities
activityLogSchema.statics.getRecentActivities = function(limit = 50, filter = {}) {
    return this.find(filter)
        .populate('user.id', 'name username code')
        .populate('target.id', 'name username code')
        .sort({ createdAt: -1 })
        .limit(limit);
};

// Static method to get activities by user
activityLogSchema.statics.getUserActivities = function(userId, limit = 20) {
    return this.find({ 'user.id': userId })
        .sort({ createdAt: -1 })
        .limit(limit);
};

// Static method to get security events
activityLogSchema.statics.getSecurityEvents = function(limit = 100) {
    return this.find({
        severity: { $in: ['high', 'critical'] }
    })
        .sort({ createdAt: -1 })
        .limit(limit);
};

// Index for better query performance
activityLogSchema.index({ 'user.id': 1 });
activityLogSchema.index({ 'target.id': 1 });
activityLogSchema.index({ action: 1 });
activityLogSchema.index({ createdAt: -1 });
activityLogSchema.index({ severity: 1 });
activityLogSchema.index({ status: 1 });

// Compound indexes
activityLogSchema.index({ 'user.id': 1, createdAt: -1 });
activityLogSchema.index({ action: 1, createdAt: -1 });
activityLogSchema.index({ severity: 1, createdAt: -1 });

module.exports = mongoose.model('ActivityLog', activityLogSchema);