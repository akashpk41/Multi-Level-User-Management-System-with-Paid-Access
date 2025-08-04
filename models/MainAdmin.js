const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const mainAdminSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required'],
        unique: true,
        trim: true,
        lowercase: true,
        minLength: [3, 'Username must be at least 3 characters'],
        maxLength: [20, 'Username cannot exceed 20 characters']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minLength: [6, 'Password must be at least 6 characters']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        trim: true,
        lowercase: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
    },
    name: {
        type: String,
        required: [true, 'Name is required'],
        trim: true,
        maxLength: [50, 'Name cannot exceed 50 characters']
    },
    // Device Locking (Main admin can login to 3 devices simultaneously)
    devices: [{
        deviceId: {
            type: String,
            required: true
        },
        deviceName: {
            type: String,
            default: 'Unknown Device'
        },
        userAgent: String,
        ip: String,
        lastActive: {
            type: Date,
            default: Date.now
        },
        refreshToken: String
    }],
    maxDevices: {
        type: Number,
        default: 3,
        min: 1,
        max: 5
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
    // System Configuration
    crashValue: {
        type: Number,
        default: 2.5,
        min: [1.0, 'Crash value must be at least 1.0'],
        max: [10.0, 'Crash value cannot exceed 10.0']
    },
    // Stats
    totalSubAdmins: {
        type: Number,
        default: 0
    },
    totalUsers: {
        type: Number,
        default: 0
    },
    // Security
    twoFactorEnabled: {
        type: Boolean,
        default: false
    },
    twoFactorSecret: {
        type: String,
        default: null
    },
    // Account status
    isActive: {
        type: Boolean,
        default: true
    },
    // Last activity for security monitoring
    lastActivity: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true,
    toJSON: {
        virtuals: true,
        transform: function(doc, ret) {
            delete ret.password;
            delete ret.refreshToken;
            delete ret.twoFactorSecret;
            return ret;
        }
    },
    toObject: { virtuals: true }
});

// Virtual for system stats
mainAdminSchema.virtual('systemStats').get(function() {
    return {
        totalSubAdmins: this.totalSubAdmins,
        totalUsers: this.totalUsers,
        crashValue: this.crashValue,
        lastActivity: this.lastActivity
    };
});

// Password hashing before save
mainAdminSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();

    try {
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Update last activity
mainAdminSchema.pre('save', function(next) {
    if (this.isModified() && !this.isModified('lastActivity')) {
        this.lastActivity = new Date();
    }
    next();
});

// Method to compare password
mainAdminSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Method to update crash value
mainAdminSchema.methods.updateCrashValue = function(newValue) {
    if (newValue >= 1.0 && newValue <= 10.0) {
        this.crashValue = newValue;
        return true;
    }
    return false;
};

// Method to update system stats
mainAdminSchema.methods.updateStats = async function() {
    try {
        const SubAdmin = mongoose.model('SubAdmin');
        const User = mongoose.model('User');

        this.totalSubAdmins = await SubAdmin.countDocuments();
        this.totalUsers = await User.countDocuments();

        await this.save();
        return true;
    } catch (error) {
        console.error('Error updating stats:', error);
        return false;
    }
};

// Static method to create default main admin
mainAdminSchema.statics.createDefaultAdmin = async function() {
    try {
        const existingAdmin = await this.findOne();
        if (existingAdmin) {
            return existingAdmin;
        }

        const defaultAdmin = new this({
            username: process.env.MAIN_ADMIN_USERNAME || 'mainadmin',
            password: process.env.MAIN_ADMIN_PASSWORD || 'Admin@123456',
            email: process.env.MAIN_ADMIN_EMAIL || 'admin@example.com',
            name: 'Main Administrator',
            crashValue: parseFloat(process.env.CRASH_VALUE) || 2.5
        });

        await defaultAdmin.save();
        console.log('✅ Default main admin created successfully');
        return defaultAdmin;
    } catch (error) {
        console.error('❌ Error creating default admin:', error);
        throw error;
    }
};

// Index for better performance
mainAdminSchema.index({ username: 1 });
mainAdminSchema.index({ email: 1 });
mainAdminSchema.index({ deviceId: 1 });
mainAdminSchema.index({ isActive: 1 });

module.exports = mongoose.model('MainAdmin', mainAdminSchema);