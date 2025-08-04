const moment = require('moment');

// Calculate package expiry based on package type
const calculatePackageExpiry = (packageType, startDate = new Date()) => {
    const start = moment(startDate);

    switch (packageType) {
        case '24h':
            return start.add(24, 'hours').toDate();
        case '3d':
            return start.add(3, 'days').toDate();
        case '7d':
            return start.add(7, 'days').toDate();
        default:
            return start.add(24, 'hours').toDate();
    }
};

// Calculate payment expiry (default 30 days)
const calculatePaymentExpiry = (days = 30, startDate = new Date()) => {
    return moment(startDate).add(days, 'days').toDate();
};

// Check if date is expired
const isExpired = (expiryDate) => {
    return moment().isAfter(moment(expiryDate));
};

// Get remaining time until expiry
const getRemainingTime = (expiryDate) => {
    if (isExpired(expiryDate)) return null;

    const now = moment();
    const expiry = moment(expiryDate);
    const duration = moment.duration(expiry.diff(now));

    return {
        days: Math.floor(duration.asDays()),
        hours: duration.hours(),
        minutes: duration.minutes(),
        seconds: duration.seconds(),
        totalMinutes: Math.floor(duration.asMinutes()),
        totalSeconds: Math.floor(duration.asSeconds())
    };
};

// Get human readable time remaining
const getHumanReadableTime = (expiryDate) => {
    const remaining = getRemainingTime(expiryDate);

    if (!remaining) return 'Expired';

    if (remaining.days > 0) {
        return `${remaining.days} day${remaining.days > 1 ? 's' : ''} ${remaining.hours} hour${remaining.hours !== 1 ? 's' : ''}`;
    } else if (remaining.hours > 0) {
        return `${remaining.hours} hour${remaining.hours > 1 ? 's' : ''} ${remaining.minutes} minute${remaining.minutes !== 1 ? 's' : ''}`;
    } else if (remaining.minutes > 0) {
        return `${remaining.minutes} minute${remaining.minutes > 1 ? 's' : ''}`;
    } else {
        return `${remaining.seconds} second${remaining.seconds !== 1 ? 's' : ''}`;
    }
};

// Format date for display
const formatDate = (date, format = 'YYYY-MM-DD HH:mm:ss') => {
    return moment(date).format(format);
};

// Format date relative to now (e.g., "2 hours ago")
const formatRelativeTime = (date) => {
    return moment(date).fromNow();
};

// Get date range for queries
const getDateRange = (period) => {
    const now = moment();
    let startDate, endDate;

    switch (period) {
        case 'today':
            startDate = now.clone().startOf('day');
            endDate = now.clone().endOf('day');
            break;
        case 'yesterday':
            startDate = now.clone().subtract(1, 'day').startOf('day');
            endDate = now.clone().subtract(1, 'day').endOf('day');
            break;
        case 'thisWeek':
            startDate = now.clone().startOf('week');
            endDate = now.clone().endOf('week');
            break;
        case 'lastWeek':
            startDate = now.clone().subtract(1, 'week').startOf('week');
            endDate = now.clone().subtract(1, 'week').endOf('week');
            break;
        case 'thisMonth':
            startDate = now.clone().startOf('month');
            endDate = now.clone().endOf('month');
            break;
        case 'lastMonth':
            startDate = now.clone().subtract(1, 'month').startOf('month');
            endDate = now.clone().subtract(1, 'month').endOf('month');
            break;
        case 'last7Days':
            startDate = now.clone().subtract(7, 'days').startOf('day');
            endDate = now.clone().endOf('day');
            break;
        case 'last30Days':
            startDate = now.clone().subtract(30, 'days').startOf('day');
            endDate = now.clone().endOf('day');
            break;
        default:
            startDate = now.clone().startOf('day');
            endDate = now.clone().endOf('day');
    }

    return {
        startDate: startDate.toDate(),
        endDate: endDate.toDate()
    };
};

// Check if date is within range
const isWithinRange = (date, startDate, endDate) => {
    const checkDate = moment(date);
    return checkDate.isBetween(moment(startDate), moment(endDate), null, '[]');
};

// Add time to date
const addTime = (date, amount, unit) => {
    return moment(date).add(amount, unit).toDate();
};

// Subtract time from date
const subtractTime = (date, amount, unit) => {
    return moment(date).subtract(amount, unit).toDate();
};

// Get start and end of day
const getStartOfDay = (date = new Date()) => {
    return moment(date).startOf('day').toDate();
};

const getEndOfDay = (date = new Date()) => {
    return moment(date).endOf('day').toDate();
};

// Get timezone info
const getTimezoneInfo = () => {
    const now = moment();
    return {
        timezone: moment.tz.guess(),
        offset: now.format('Z'),
        offsetMinutes: now.utcOffset()
    };
};

// Convert to user timezone (if needed later)
const convertToTimezone = (date, timezone) => {
    return moment.tz(date, timezone).toDate();
};

// Validate date string
const isValidDate = (dateString) => {
    return moment(dateString).isValid();
};

// Get age of date (how old it is)
const getAge = (date) => {
    const now = moment();
    const targetDate = moment(date);
    const duration = moment.duration(now.diff(targetDate));

    return {
        years: Math.floor(duration.asYears()),
        months: Math.floor(duration.asMonths()),
        days: Math.floor(duration.asDays()),
        hours: Math.floor(duration.asHours()),
        minutes: Math.floor(duration.asMinutes()),
        seconds: Math.floor(duration.asSeconds())
    };
};

// Check if date is in future
const isFuture = (date) => {
    return moment(date).isAfter(moment());
};

// Check if date is in past
const isPast = (date) => {
    return moment(date).isBefore(moment());
};

// Get business days between two dates (excluding weekends)
const getBusinessDays = (startDate, endDate) => {
    let start = moment(startDate);
    const end = moment(endDate);
    let businessDays = 0;

    while (start.isSameOrBefore(end)) {
        if (start.day() !== 0 && start.day() !== 6) { // Not Sunday (0) or Saturday (6)
            businessDays++;
        }
        start.add(1, 'day');
    }

    return businessDays;
};

// Get next business day
const getNextBusinessDay = (date = new Date()) => {
    let nextDay = moment(date).add(1, 'day');

    while (nextDay.day() === 0 || nextDay.day() === 6) {
        nextDay.add(1, 'day');
    }

    return nextDay.toDate();
};

// Format duration in human readable format
const formatDuration = (milliseconds) => {
    const duration = moment.duration(milliseconds);
    const days = Math.floor(duration.asDays());
    const hours = duration.hours();
    const minutes = duration.minutes();
    const seconds = duration.seconds();

    let result = [];

    if (days > 0) result.push(`${days} day${days > 1 ? 's' : ''}`);
    if (hours > 0) result.push(`${hours} hour${hours > 1 ? 's' : ''}`);
    if (minutes > 0) result.push(`${minutes} minute${minutes > 1 ? 's' : ''}`);
    if (seconds > 0 && result.length === 0) result.push(`${seconds} second${seconds > 1 ? 's' : ''}`);

    return result.length > 0 ? result.join(' ') : '0 seconds';
};

module.exports = {
    calculatePackageExpiry,
    calculatePaymentExpiry,
    isExpired,
    getRemainingTime,
    getHumanReadableTime,
    formatDate,
    formatRelativeTime,
    getDateRange,
    isWithinRange,
    addTime,
    subtractTime,
    getStartOfDay,
    getEndOfDay,
    getTimezoneInfo,
    convertToTimezone,
    isValidDate,
    getAge,
    isFuture,
    isPast,
    getBusinessDays,
    getNextBusinessDay,
    formatDuration
};