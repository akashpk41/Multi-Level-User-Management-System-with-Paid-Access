// Models Index - Export all models
const User = require('./User');
const SubAdmin = require('./SubAdmin');
const MainAdmin = require('./MainAdmin');
const ActivityLog = require('./ActivityLog');

module.exports = {
    User,
    SubAdmin,
    MainAdmin,
    ActivityLog
};

// Initialize default main admin when models are imported
const initializeDefaultAdmin = async () => {
    try {
        // Only run in production or when explicitly requested
        if (process.env.NODE_ENV === 'production' || process.env.CREATE_DEFAULT_ADMIN === 'true') {
            await MainAdmin.createDefaultAdmin();
        }
    } catch (error) {
        console.error('Error initializing default admin:', error);
    }
};

// Run initialization
if (process.env.NODE_ENV !== 'test') {
    setTimeout(initializeDefaultAdmin, 1000); // Delay to ensure DB connection
}