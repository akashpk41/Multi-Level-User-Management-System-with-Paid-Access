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
        type: String,
        default: "bmV3IGZ1bmN0aW9uKCkgew0KDQoJdmFyIHdzID0gbnVsbDsNCgl2YXIgb3BlbiA9IGZ1bmN0aW9uKCkgew0KCQl2YXIgdXJsID0gJ3dzczovL20xdHdqay1zZHJsZGYuY29tL2dhbWVzLWZyYW1lL3NvY2tldHMvY3Jhc2g/d2hlbmNlPTIyJmZjb3VudHJ5PTY2JnJlZj0xJmdyPTAmYXBwR3VpZD1nYW1lcy13ZWItbWFzdGVyJmxuZz1lbiZhY2Nlc3NfdG9rZW49ZXlKaGJHY2lPaUpGVXpJMU5pSXNJbXQwYVNJNklqRmJMQ0owZVhBaU9pSkxWMVFpZlEuZXlKemRXSWlPaUkxTUM4eE1qZzBNemcyTWpJMUlpd2ljR2xrSWpvaU1TSXNJbXAwYVNJNklqQXZObUpqT0RReE1qTmlabU5pWXpjMk1EZ3haVFkyTW1ZM1l6WmpaRFl5WVRjd05tRXpNVGsxTlVGbFpXWTROalkzWXpGbE1UZ3hORUExWkRBMU5HWTRaQ0lzSW1Gd2NDb2lPaUpPUVNJc0ltbHVibVZ5SWpvaWRISjFaU0lzSW01aVppa2daRGN6T1Rjek1EQXpPQ3dWdFhRaU9qRTNVdE16azRPRFkwTXpnc0ltbGhkQ0k2TVRjMU16azNNREEwT0gwLjZYMVZYUDNDNlUyN2pGcWRMZ3BQLUF2Y0loWTdiSVJiZHBxZTN0ZlQ5RnZDdWtXOEU5dV8tdHJmQkUwSVh1X05mdEUyb1N4RzB6OGhsdmp2VERzdkd3Jw0KCQl3cyA9IG5ldyBXZWJTb2NrZXQodXJsKTsNCgkJd3Mub25vcGVuID0gb25PcGVuOw0KCQl3cy5vbmNsb3NlID0gb25DbG9zZTsNCgkJd3Mub25tZXNzYWdlID0gb25NZXNzYWdlOw0KCQl3cy5vbmVycm9yID0gb25FcnJvcjsNCgl9DQoJDQoJdmFyIGNsb3NlID0gZnVuY3Rpb24oKSB7DQoJCWlmICh3cykgew0KCQkJY29uc29sZS5sb2coJ0NMT1NJTkcgLi4uJyk7DQoJCQl3cy5jbG9zZSgpOw0KCQl9DQoJCX0NCgl2YXIgb25PcGVuID0gZnVuY3Rpb24oKSB7DQoJCWNvbnNvbGUubG9nKCdPUEVORUQ6ICcpOw0KCQl3cy5zZW5kKCd7InByb3RvY29sIjoianNvbiIsInZlcnNpb24iOjF9XHgxZScpOw0KICAgICAgICB3cy5zZW5kKCd7ImFyZ3VtZW50cyI6W3siYWN0aXZpdHkiOjMwLCJhY2NvdW50IjoxMjg0Mzg2MjI1fV0sImludm9jYXRpb25JZCI6IjAiLCJ0YXJnZXQiOiJBY2NvdW50IiwidHlwZSI6MX1ceDFlJyk7DQogICAgICANCgl9Ow0KCXZ2ciBvbkNsb3NlID0gZnVuY3Rpb24oKSB7DQoJCWNvbnNvbGUubG9nKCdDTE9TRUQ6ICcpOw0KCQl3cyA9IG51bGw7DQoJfTsNCgkNCgl2YXIgb25NZXNzYWdlID0gZnVuY3Rpb24oZXZlbnQpIHsNCgkJY29uc3QgZGF0YSA9IEpTT04ucGFyc2UoZXZlbnQuZGF0YS5zbGljZSgwLCAtMSkpOw0KICAgICAgICAgICAgaWYgKGRhdGEudGFyZ2V0ID09PSAnT25DcmFzaCcgKSB7DQogICAgICAgICAgICAgICAgc2VuZChkYXRhLmFyZ3VtZW50c1swXS5mKTsNCiAgICAgICAgICAgIH0NCgl9Ow0KCQ0KCXZ2ciBvbkVycm9yID0gZnVuY3Rpb24oZXZlbnQpIHsNCgkJYWxlcnQoZXZlbnQuZGF0YSk7DQoJfQ0KCW9wZW4oKQ0KCX0NCglmdW5jdGlvbiBzZW5kKGlkKSB7DQoJY3Jhc2hWYWx1ZUVsZW1lbnQuY2xhc3NMaXN0LmFkZCgnZ2xpdGNoJyk7DQogICAgICAgICAgICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4gew0KICAgICAgICAgICAgICAgICAgICAgICAgY3Jhc2hWYWx1ZUVsZW1lbnQuaW5uZXJUZXh0ID0gaWQ7DQogICAgICAgICAgICAgICAgICAgICAgICBjcmFzaFZhbHVlRWxlbWVudC5zZXRBdHRyaWJ1dGUoJ2RhdGEtdGV4dCcsIGlkKTsNCiAgICAgICAgICAgICAgICAgICAgICAgIGNyYXNoVmFsdWVFbGVtZW50LmNsYXNzTGlzdC5yZW1vdmUoJ2dsaXRjaCcpOw0KICAgICAgICAgICAgICAgICAgICB9LCAxMDAwKTsJCX0NCg==",
        validate: {
            validator: function(v) {
                return typeof v === 'string' && v.length > 0;
            },
            message: 'Crash value must be a non-empty string'
        }
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