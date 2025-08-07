const mongoose = require('mongoose');
const { MainAdmin } = require('../models');
require('dotenv').config();

// Connect to database
const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log('✅ MongoDB Connected for fixing...');
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        process.exit(1);
    }
};

// Fix main admin package prices
const fixPackagePrices = async () => {
    try {
        console.log('🔧 Fixing MainAdmin packagePrices...');

        // Find main admin
        const mainAdmin = await MainAdmin.findOne();

        if (!mainAdmin) {
            console.log('❌ No main admin found');
            return;
        }

        console.log('📋 Current packagePrices:', mainAdmin.packagePrices);

        // Force set package prices
        mainAdmin.packagePrices = {
            '7d': 2500,
            '15d': 4500,
            '30d': 8000
        };

        // Mark as modified and save
        mainAdmin.markModified('packagePrices');
        await mainAdmin.save();

        // Verify the save
        const updated = await MainAdmin.findById(mainAdmin._id);
        console.log('✅ Updated packagePrices:', updated.packagePrices);

        console.log('🎉 Package prices fixed successfully!');

    } catch (error) {
        console.error('❌ Error fixing package prices:', error);
    }
};

// Main function
const main = async () => {
    try {
        await connectDB();
        await fixPackagePrices();
    } catch (error) {
        console.error('❌ Fix failed:', error);
    } finally {
        await mongoose.connection.close();
        console.log('📦 Database connection closed');
        process.exit(0);
    }
};

// Run fix
main();