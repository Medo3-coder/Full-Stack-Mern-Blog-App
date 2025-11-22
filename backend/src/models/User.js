const mongoose = require("mongoose");
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema(
  {
    firstName: {
      type: String,
      required: [true, "First name is required"],
      trim: true,
    },
    lastName: {
      type: String,
      required: [true, "Last name is required"],
      trim: true,
    },
    image: {
      type: String,
      default:
        "https://media.istockphoto.com/id/1451587807/vector/user-profile-icon-vector-avatar-or-person-icon-profile-picture-portrait-symbol-vector.jpg?s=2048x2048&w=is&k=20&c=-g-2McKwLpsyYHPDT3Wf1oo2ppTmNxq797heiFJmwSM=",
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      trim: true,
    },
    bio: {
      type: String,
      trim: true,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [6, "Password must be at least 6 characters long"],
      select: false, // Exclude from query results by default ✅ Hide password by default
    },

    passwordConfirm: {
      type: String,
      required: [true, "Please confirm your password"],
      validate: {
        // This only works on CREATE and SAVE!!!
        validator: function (el) {
          return el === this.password;
        },
        message: "Passwords do not match",
      },
    },
    postCount: {
      type: Number,
      default: 0,
    },
    isBlocked: {
      type: Boolean,
      default: false,
    },
    isAdmin: {
      type: Boolean,
      default: false,
    },
    role: {
      type: String,
      enum: ["Admin", "Guest", "Blogger"],
      default: "Guest",
    },
    isFollowing: {
      type: Boolean,
      default: false,
    },
    isUnFollowing: {
      type: Boolean,
      default: false,
    },
    isAccountVerified: {
      type: Boolean,
      default: false,
    },
    viewedBy: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],

    following: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],

    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetTokenExpires: Date,
    accountVerificationToken: String,
    accountVerificationTokenExpires: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,

    active: {
      type: Boolean,
      default: true,
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Hash password before saving if modified
userSchema.pre("save", async function (next) {
  // Delete passwordConfirm field - we don't want to store it in DB
  // This must happen before password hashing check
  if (this.passwordConfirm !== undefined) {
    this.passwordConfirm = undefined;
  }

  // Only run password hashing if password was actually modified
  if (!this.isModified("password")) return next();

  // Hash the password
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  
  // set passwordChangedAt slightly in the past to ensure token created right now is valid
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

// Instance method - compare password
userSchema.methods.correctPassword = async function (candidatePassword ,userPassword) {
  return bcrypt.compare(candidatePassword, userPassword);
};

// Instance method - check if password changed after token issued (iat in seconds)
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000 , 10);
    return JWTTimestamp < changedTimestamp; // true means password changed after token issued
  }
  // not changed
  return false;
};

// Create password reset token (returns plain token; stores hashed token & expiry)
userSchema.methods.createPasswordResetToken = function () {
  // plain token to send to user
  const resetToken = crypto.randomBytes(32).toString("hex"); 
  // store hashed token in DB
  this.passwordResetToken = crypto.createHash("sha256").update(resetToken).digest("hex"); 
  // expires in 10 minutes by default
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
  return resetToken;
};

// Create account verify token (similar pattern)
userSchema.methods.createAccountVerifyToken = function () {
  const token = crypto.randomBytes(32).toString("hex");
  this.accountVerificationToken = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
  // expire in 24 hours
  this.accountVerificationTokenExpires = Date.now() + 24 * 60 * 60 * 1000;
  return token;
};

const User = mongoose.model("User", userSchema);

module.exports = User;
