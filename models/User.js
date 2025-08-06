const mongoose = require("mongoose");
const moment = require("moment");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
      maxLength: [50, "Name cannot exceed 50 characters"],
    },
    code: {
      type: String,
      required: [true, "User code is required"],
      unique: true,
      trim: true,
      uppercase: true,
      match: [
        /^[A-Z0-9]{6,12}$/,
        "Code must be 6-12 characters long and contain only letters and numbers",
      ],
    },
    subAdmin: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "SubAdmin",
      required: [true, "Sub Admin reference is required"],
    },
    package: {
      type: String,
      enum: ["24h", "3d", "7d"],
      required: [true, "Package type is required"],
    },
    packageExpiry: {
      type: Date,
      required: [true, "Package expiry is required"],
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    deviceId: {
      type: String,
      default: null,
      // যখন user login করবে তখন এটা set হবে
    },
    lastLogin: {
      type: Date,
      default: null,
    },
    loginCount: {
      type: Number,
      default: 0,
    },
    refreshToken: {
      type: String,
      default: null,
    },
    // Auto logout tracking
    isAutoLoggedOut: {
      type: Boolean,
      default: false,
    },
    autoLogoutReason: {
      type: String,
      enum: ["expired", "sub_admin_deleted", "device_change", "manual", null],
      default: null,
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Virtual for checking if package is expired
userSchema.virtual("isExpired").get(function () {
  return moment().isAfter(this.packageExpiry);
});

// Virtual for remaining time
userSchema.virtual("remainingTime").get(function () {
  if (this.isExpired) return null;

  const now = moment();
  const expiry = moment(this.packageExpiry);
  const duration = moment.duration(expiry.diff(now));

  return {
    days: Math.floor(duration.asDays()),
    hours: duration.hours(),
    minutes: duration.minutes(),
    totalMinutes: Math.floor(duration.asMinutes()),
  };
});

// Method to set package expiry based on package type
userSchema.methods.setPackageExpiry = function () {
  const now = moment();

  switch (this.package) {
    case "24h":
      this.packageExpiry = now.add(24, "hours").toDate();
      break;
    case "3d":
      this.packageExpiry = now.add(3, "days").toDate();
      break;
    case "7d":
      this.packageExpiry = now.add(7, "days").toDate();
      break;
    default:
      this.packageExpiry = now.add(24, "hours").toDate();
  }
};

// Method to check and auto logout if expired
userSchema.methods.checkAndAutoLogout = function () {
  if (this.isExpired && this.isActive) {
    this.isActive = false;
    this.isAutoLoggedOut = true;
    this.autoLogoutReason = "expired";
    this.refreshToken = null;
    this.deviceId = null;
    return true;
  }
  return false;
};

// Pre-save middleware to set expiry if new user
userSchema.pre("save", function (next) {
  if (this.isNew && !this.packageExpiry) {
    this.setPackageExpiry();
  }
  next();
});

// Index for better query performance
userSchema.index({ code: 1 });
userSchema.index({ subAdmin: 1 });
userSchema.index({ packageExpiry: 1 });
userSchema.index({ isActive: 1 });
userSchema.index({ deviceId: 1 });

module.exports = mongoose.model("User", userSchema);
