const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const moment = require('moment');

const subAdminSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required'],
        unique: true,
        trim: true,
        lowercase: true,
        minLength: [3, 'Username must be at least 3 characters'],
        maxLength: [20, 'Username cannot exceed 20 characters'],
        match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers and underscores']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minLength: [6, 'Password must be at least 6 characters']
    },
    name: {
        type: String,
        required: [true, 'Name is required'],
        trim: true,
        maxLength: [50, 'Name cannot exceed 50 characters']
    },
    // Package System
    package: {
        type: String,
        enum: ['7d', '15d', '30d'],
        required: [true, 'Package type is required']
    },
    packagePrice: {
        type: Number,
        required: [true, 'Package price is required'],
        min: [0, 'Package price cannot be negative']
    },
    packageExpiry: {
        type: Date,
        required: [true, 'Package expiry is required']
    },
    isPaid: {
        type: Boolean,
        default: false
    },
    isActive: {
        type: Boolean,
        default: false // Main admin manually activate করবে
    },
    // Device Locking
    deviceId: {
        type: String,
        default: null
    },
    lastLogin: {
        type: Date,
        default: null
    },
    loginCount: {
        type: Number,
        default: 0
    },
    refreshToken: {
        type: String,
        default: null
    },
    // User Management Stats
    totalUsersAdded: {
        type: Number,
        default: 0
    },
    activeUsers: {
        type: Number,
        default: 0
    },
    // Sales Tracking
    totalSales: {
        type: Number,
        default: 0,
        min: [0, 'Total sales cannot be negative']
    },
    salesHistory: [{
        amount: {
            type: Number,
            required: true
        },
        package: {
            type: String,
            enum: ['7d', '15d', '30d'],
            required: true
        },
        date: {
            type: Date,
            default: Date.now
        },
        note: {
            type: String,
            default: ''
        }
    }],
    // Auto logout tracking
    isAutoLoggedOut: {
        type: Boolean,
        default: false
    },
    autoLogoutReason: {
        type: String,
        enum: ['expired', 'payment_expired', 'main_admin_action', 'device_change', null],
        default: null
    },
    // Created by main admin
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'MainAdmin',
        required: true
    }
}, {
    timestamps: true,
    toJSON: {
        virtuals: true,
        transform: function(doc, ret) {
            delete ret.password;
            delete ret.refreshToken;
            return ret;
        }
    },
    toObject: { virtuals: true }
});

// Virtual for checking if package is expired
subAdminSchema.virtual('isPackageExpired').get(function() {
    if (!this.packageExpiry) return true;
    return moment().isAfter(this.packageExpiry);
});

// Virtual for remaining package time
subAdminSchema.virtual('remainingPackageTime').get(function() {
    if (!this.packageExpiry || this.isPackageExpired) return null;

    const now = moment();
    const expiry = moment(this.packageExpiry);
    const duration = moment.duration(expiry.diff(now));

    return {
        days: Math.floor(duration.asDays()),
        hours: duration.hours(),
        minutes: duration.minutes(),
        totalMinutes: Math.floor(duration.asMinutes())
    };
});

// Virtual to check if can access system
subAdminSchema.virtual('canAccess').get(function() {
    return this.isActive && this.isPaid && !this.isPackageExpired;
});

// Password hashing before save
subAdminSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();

    try {
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Method to compare password
subAdminSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Method to set package expiry and price
subAdminSchema.methods.setPackage = function(packageType, customPrice = null) {
    const now = moment();

    // Default prices
    const prices = {
        '7d': 2500,
        '15d': 4500,
        '30d': 8000
    };

    this.package = packageType;
    this.packagePrice = customPrice || prices[packageType];

    switch(packageType) {
        case '7d':
            this.packageExpiry = now.add(7, 'days').toDate();
            break;
        case '15d':
            this.packageExpiry = now.add(15, 'days').toDate();
            break;
        case '30d':
            this.packageExpiry = now.add(30, 'days').toDate();
            break;
        default:
            this.packageExpiry = now.add(7, 'days').toDate();
    }

    this.isPaid = true;
    this.isActive = true;

    // Add to sales history
    this.salesHistory.push({
        amount: this.packagePrice,
        package: packageType,
        date: new Date(),
        note: `Package activated: ${packageType}`
    });

    // Update total sales
    this.totalSales += this.packagePrice;
};

// Method to check and auto logout if expired
subAdminSchema.methods.checkAndAutoLogout = async function() {
    if ((this.isPackageExpired || !this.isActive) && this.refreshToken) {
        this.isAutoLoggedOut = true;
        this.autoLogoutReason = this.isPackageExpired ? 'expired' : 'main_admin_action';
        this.refreshToken = null;
        this.deviceId = null;

        // Also logout all users under this sub-admin
        const User = mongoose.model('User');
        await User.updateMany(
            { subAdmin: this._id, isActive: true },
            {
                isActive: false,
                isAutoLoggedOut: true,
                autoLogoutReason: 'sub_admin_deleted',
                refreshToken: null,
                deviceId: null
            }
        );

        return true;
    }
    return false;
};

// Static method to find active sub-admins
subAdminSchema.statics.findActive = function() {
    return this.find({
        isActive: true,
        isPaid: true,
        packageExpiry: { $gt: new Date() }
    });
};

// Static method to get package prices
subAdminSchema.statics.getPackagePrices = function() {
    return {
        '7d': 2500,
        '15d': 4500,
        '30d': 8000
    };
};

// Static method to get total sales
subAdminSchema.statics.getTotalSales = async function() {
    const result = await this.aggregate([
        {
            $group: {
                _id: null,
                totalSales: { $sum: '$totalSales' },
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

    return result[0] || { totalSales: 0, totalSubAdmins: 0, activeSubAdmins: 0 };
};

// Index for better performance
subAdminSchema.index({ username: 1 });
subAdminSchema.index({ isActive: 1 });
subAdminSchema.index({ isPaid: 1 });
subAdminSchema.index({ packageExpiry: 1 });
subAdminSchema.index({ deviceId: 1 });
subAdminSchema.index({ createdBy: 1 });

module.exports = mongoose.model('SubAdmin', subAdminSchema);