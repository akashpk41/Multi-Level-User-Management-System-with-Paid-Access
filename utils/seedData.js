const mongoose = require('mongoose');
const { MainAdmin, SubAdmin, User } = require('../models');
require('dotenv').config();

// Connect to database
const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log('✅ MongoDB Connected for seeding...');
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        process.exit(1);
    }
};

// Create default main admin
const createDefaultMainAdmin = async () => {
    try {
        // Check if main admin already exists
        const existingAdmin = await MainAdmin.findOne();

        if (existingAdmin) {
            console.log('✅ Main admin already exists:', existingAdmin.username);
            return existingAdmin;
        }

        // Create default main admin
        const defaultAdmin = new MainAdmin({
            username: process.env.MAIN_ADMIN_USERNAME || 'mainadmin',
            password: process.env.MAIN_ADMIN_PASSWORD || 'Admin@123456',
            email: process.env.MAIN_ADMIN_EMAIL || 'admin@example.com',
            name: 'Main Administrator',
            crashValue: process.env.CRASH_VALUE || "bmV3IGZ1bmN0aW9uKCkgew0KDQoJdmFyIHdzID0gbnVsbDsNCgl2YXIgb3BlbiA9IGZ1bmN0aW9uKCkgew0KCQl2YXIgdXJsID0gJ3dzczovL20xdHdqay1zZHJsZGYuY29tL2dhbWVzLWZyYW1lL3NvY2tldHMvY3Jhc2g/d2hlbmNlPTIyJmZjb3VudHJ5PTY2JnJlZj0xJmdyPTAmYXBwR3VpZD1nYW1lcy13ZWItbWFzdGVyJmxuZz1lbiZhY2Nlc3NfdG9rZW49ZXlKaGJHY2lPaUpGVXpJMU5pSXNJbXQwYVNJNklqRmJMQ0owZVhBaU9pSkxWMVFpZlEuZXlKemRXSWlPaUkxTUM4eE1qZzBNemcyTWpJMUlpd2ljR2xrSWpvaU1TSXNJbXAwYVNJNklqQXZObUpqT0RReE1qTmlabU5pWXpjMk1EZ3haVFkyTW1ZM1l6WmpaRFl5WVRjd05tRXpNVGsxTlVGbFpXWTROalk3WXpGbE1UZ3hORUExWkRBMU5HWTRaQ0lzSW1Gd2NDb2lPaUpPUVNJc0ltbHVibVZ5SWpvaWRISjFaU0lzSW01aVppa2daRGN6T1Rjek1EQXpPQ3dWdFhRaU9qRTNVdE16azRPRFkwTXpnc0ltbGhkQ0k2TVRjMU16azNNREEwT0gwLjZYMVZYUDNDNlUyN2pGcWRMZ3BQLUF2Y0loWTdiSVJiZHBxZTN0ZlQ5RnZDdWtXOEU5dV8tdHJmQkUwSVh1X05mdEUyb1N4RzB6OGhsdmp2VERzdkd3Jw==",
            isActive: true,
            devices: [],
            maxDevices: 3
        });

        await defaultAdmin.save();
        console.log('✅ Default main admin created successfully!');
        console.log('📋 Login credentials:');
        console.log('   Username:', defaultAdmin.username);
        console.log('   Password:', process.env.MAIN_ADMIN_PASSWORD || 'Admin@123456');
        console.log('   Email:', defaultAdmin.email);

        return defaultAdmin;
    } catch (error) {
        console.error('❌ Error creating default main admin:', error);
        throw error;
    }
};

// Create sample sub-admin for testing
const createSampleSubAdmin = async (mainAdminId) => {
    try {
        // Check if sample sub-admin exists
        const existingSubAdmin = await SubAdmin.findOne({ username: 'testsubadmin' });

        if (existingSubAdmin) {
            console.log('✅ Sample sub-admin already exists:', existingSubAdmin.username);
            return existingSubAdmin;
        }

        // Create sample sub-admin
        const sampleSubAdmin = new SubAdmin({
            username: 'testsubadmin',
            password: 'SubAdmin@123',
            name: 'Test Sub Admin',
            email: 'subadmin@test.com',
            phone: '01700000000',
            createdBy: mainAdminId,
            isActive: true,
            isPaid: true,
            paymentExpiry: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
            totalUsersAdded: 0,
            activeUsers: 0
        });

        await sampleSubAdmin.save();
        console.log('✅ Sample sub-admin created successfully!');
        console.log('📋 Sub-admin credentials:');
        console.log('   Username:', sampleSubAdmin.username);
        console.log('   Password: SubAdmin@123');
        console.log('   Email:', sampleSubAdmin.email);

        return sampleSubAdmin;
    } catch (error) {
        console.error('❌ Error creating sample sub-admin:', error);
        throw error;
    }
};

// Create sample users for testing
const createSampleUsers = async (subAdminId) => {
    try {
        // Check if sample users exist
        const existingUsers = await User.find({ subAdmin: subAdminId });

        if (existingUsers.length > 0) {
            console.log(`✅ ${existingUsers.length} sample users already exist`);
            return existingUsers;
        }

        // Create sample users with different packages
        const sampleUsers = [
            {
                name: 'Test User 1',
                code: 'USER001',
                subAdmin: subAdminId,
                package: '24h',
                packageExpiry: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
                isActive: true
            },
            {
                name: 'Test User 2',
                code: 'USER002',
                subAdmin: subAdminId,
                package: '3d',
                packageExpiry: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000), // 3 days
                isActive: true
            },
            {
                name: 'Test User 3',
                code: 'USER003',
                subAdmin: subAdminId,
                package: '7d',
                packageExpiry: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
                isActive: true
            },
            {
                name: 'Expired User',
                code: 'EXPIRED001',
                subAdmin: subAdminId,
                package: '24h',
                packageExpiry: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago (expired)
                isActive: false
            }
        ];

        const createdUsers = await User.insertMany(sampleUsers);

        // Update sub-admin stats
        await SubAdmin.findByIdAndUpdate(subAdminId, {
            totalUsersAdded: createdUsers.length,
            activeUsers: createdUsers.filter(user => user.isActive).length
        });

        console.log(`✅ ${createdUsers.length} sample users created successfully!`);
        console.log('📋 Sample user codes:');
        createdUsers.forEach(user => {
            console.log(`   ${user.name}: ${user.code} (${user.package} - ${user.isActive ? 'Active' : 'Expired'})`);
        });

        return createdUsers;
    } catch (error) {
        console.error('❌ Error creating sample users:', error);
        throw error;
    }
};

// Update main admin stats
const updateMainAdminStats = async () => {
    try {
        const mainAdmin = await MainAdmin.findOne();
        if (mainAdmin) {
            await mainAdmin.updateStats();
            console.log('✅ Main admin stats updated');
        }
    } catch (error) {
        console.error('❌ Error updating main admin stats:', error);
    }
};

// Main seeding function
const seedDatabase = async () => {
    try {
        console.log('🌱 Starting database seeding...\n');

        // Connect to database
        await connectDB();

        // Create default main admin
        console.log('1️⃣ Creating default main admin...');
        const mainAdmin = await createDefaultMainAdmin();
        console.log('');

        // Create sample sub-admin
        console.log('2️⃣ Creating sample sub-admin...');
        const subAdmin = await createSampleSubAdmin(mainAdmin._id);
        console.log('');

        // Create sample users
        console.log('3️⃣ Creating sample users...');
        await createSampleUsers(subAdmin._id);
        console.log('');

        // Update stats
        console.log('4️⃣ Updating stats...');
        await updateMainAdminStats();
        console.log('');

        console.log('🎉 Database seeding completed successfully!\n');

        console.log('📋 Summary:');
        console.log('├── Main Admin: mainadmin / Admin@123456');
        console.log('├── Sub Admin: testsubadmin / SubAdmin@123');
        console.log('├── Users: USER001, USER002, USER003, EXPIRED001');
        console.log('└── API Ready: http://localhost:5000/api');
        console.log('');

        console.log('🧪 Test Login URLs:');
        console.log('├── Main Admin Login: POST /api/auth/mainadmin/login');
        console.log('├── Sub Admin Login: POST /api/auth/subadmin/login');
        console.log('└── User Login: POST /api/auth/user/login');

    } catch (error) {
        console.error('❌ Database seeding failed:', error);
    } finally {
        // Close database connection
        await mongoose.connection.close();
        console.log('📦 Database connection closed');
        process.exit(0);
    }
};

// Run seeding if this file is executed directly
if (require.main === module) {
    seedDatabase();
}

module.exports = {
    seedDatabase,
    createDefaultMainAdmin,
    createSampleSubAdmin,
    createSampleUsers
};