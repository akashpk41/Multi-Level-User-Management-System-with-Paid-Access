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
    email: {
        type: String,
        trim: true,
        lowercase: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
    },
    phone: {
        type: String,
        trim: true,
        match: [/^[0-9]{10,15}$/, 'Please enter a valid phone number']
    },
    // Payment and Access Control
    isPaid: {
        type: Boolean,
        default: false
    },
    paymentExpiry: {
        type: Date,
        default: null
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

// Virtual for checking if payment is expired
subAdminSchema.virtual('isPaymentExpired').get(function() {
    if (!this.paymentExpiry) return true;
    return moment().isAfter(this.paymentExpiry);
});

// Virtual for remaining payment time
subAdminSchema.virtual('remainingPaymentTime').get(function() {
    if (!this.paymentExpiry || this.isPaymentExpired) return null;

    const now = moment();
    const expiry = moment(this.paymentExpiry);
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
    return this.isActive && this.isPaid && !this.isPaymentExpired;
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

// Method to set payment expiry
subAdminSchema.methods.setPaymentExpiry = function(days = 30) {
    this.paymentExpiry = moment().add(days, 'days').toDate();
    this.isPaid = true;
    this.isActive = true;
};

// Method to check and auto logout if expired
subAdminSchema.methods.checkAndAutoLogout = async function() {
    if ((this.isPaymentExpired || !this.isActive) && this.refreshToken) {
        this.isAutoLoggedOut = true;
        this.autoLogoutReason = this.isPaymentExpired ? 'payment_expired' : 'main_admin_action';
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
        paymentExpiry: { $gt: new Date() }
    });
};

// Index for better performance
subAdminSchema.index({ username: 1 });
subAdminSchema.index({ isActive: 1 });
subAdminSchema.index({ isPaid: 1 });
subAdminSchema.index({ paymentExpiry: 1 });
subAdminSchema.index({ deviceId: 1 });
subAdminSchema.index({ createdBy: 1 });

module.exports = mongoose.model('SubAdmin', subAdminSchema);