const jwt = require("jsonwebtoken");
const catchAsync = require("../utils/catchAsync");
// const jwt = require("jsonwebtoken");
// const { validate } = require("../models/User");
const User = require("../models/User");
const AppError = require("../utils/appError");
const { promisify } = require("util");

const signToken = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);

  // Cookie options
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 + 60 * 1000
    ),
    httpOnly: true, // not accessible by JS
    sameSite: "Lax", // helps CSRF; consider 'Strict' for more protection
  };

  if (process.env.NODE_ENV === "production") cookieOptions.secure = true; // only send on HTTPS in production

  res.cookie("jwt", token, cookieOptions); // set cookie in response

  // hide password
  user.password = undefined; // we don't want to send password back in response

  res.status(statusCode).json({
    status: "success",
    token,
    data: { user },
  });
};

// signup
exports.signup = catchAsync(async (req, res, next) => {
  // whitelist fields to avoid mass-assignment vulnerabilities
  const { firstName, lastName, email, password, passwordConfirm, role } = req.body;

  const newUser = await User.create({
    firstName,
    lastName,
    email,
    password,
    passwordConfirm,
    role,
  });

  res.status(201).json({
    status: "success",
    data: {
      user: newUser,
    },
  });

  // Optionally send welcome email with verification link
//   try {
//     const verifyToken = newUser.createAccountVerifyToken();
//     await newUser.save({ validateBeforeSave: false }); // disable validation for other fields
//     const verfiyURL = `${req.protocol}://${req.get("host")}/api/v1/auth/verifyAccount/${verifyToken}`;
//     await sendEmail(newUser, verfiyURL).sendWelcome(); // implement sendWelcome to include verifyURL
//   } catch (err) {
//     console.error("Error sending welcome email:", err);
//   }
//   createSendToken(newUser, 201, res);
});

// LOGIN
exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // 1) Check if email and password exist
  if (!email || !password) {
    return next(new AppError("Please provide email and password!", 400));
  }

  // 2) Check if user exists && password is correct
  const user = await User.findOne({ email }).select("+password"); // explicitly select password field

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError("Incorrect email or password", 401));
  }

  if (user.isBlocked) {
    return next(new AppError("Your account has been blocked. Please contact support.", 403));
  }

  // 3) If everything ok, send token to client
  createSendToken(user, 200, res);
});

//LOGOUT (clear cookie)
exports.logout = (req, res) => {
  res.cookie("jwt", "loggedout", {
    expires: new Date(Date.now() + 10 * 1000), // expires in 10 seconds
    httpOnly: true, // not accessible by JS
  });
  res.status(200).json({ status: "success" });
};


// PROTECT middleware
exports.protect = catchAsync(async (req , res , next) => {
    // 1) Get token from header or cookie
    let token; 
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')){
        token = req.headers.authorization.split(' ')[1]; 
    } else if (req.cookies && req.cookies.jwt){ 
        token = req.cookies.jwt;
    }
    if (!token) {
        return next(new AppError('You are not logged in! Please log in to get access.', 401));
    }
    // 2) Verify token
    const decoded = await promisify(jwt.verify)(token , process.env.JWT_SECRET);

    // Check user still exists
    const currentUser = await User.findById(decoded.id).select('+password');
    if(!currentUser){
        return next(new AppError('The user belonging to this token no longer exists.', 401));
    }

    // Check if user changed password after token issued
    if(currentUser.changedPasswordAfter(decoded.iat)){
        return next(new AppError('User recently changed password! Please log in again.', 401));
    }

    // Attach user to request (without password)
    req.user = currentUser;
    req.user.password = undefined; // remove password before attaching
    next();
});

// restrictTo middleware
exports.restrictTo = (...roles) => {
    return (req, res, next) => {  // Add this return function wrapper
        if(!roles.includes(req.user.role)){ 
            return next(new AppError('You do not have permission to perform this action', 403));
        }
        next();
    };
};

//Forgot password
exports.forgotPassword = catchAsync(async (req , res , next) => {
    // 1) Get user by email 
    const user = await User.findOne({email : req.body.email });
    if(!user) return next(new AppError('There is no user with that email address.', 404));

    // 2) Create reset token
    const resetToken = User.createPasswordResetToken();
    await user.save({ validateBeforeSave: false }); // disable validation for other fields

    // 3) Send reset token to user's email
    try { 
        const resetURL = `${req.protocol}://${req.get('host')}/api/v1/auth/resetPassword/${resetToken}`;
        // hint: implement sendPasswordReset to include resetURL 
        await sendEmail(user , resetURL).sendPasswordReset(); 
        res.status(200).json({status: 'success' , message: 'Token sent to email!'});
    } catch (err) {
        // rollback token fields
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({ validateBeforeSave: false });
        return next(new AppError('There was an error sending the email. Try again later!', 500));

    }
});





