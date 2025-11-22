// restrictTo middleware
export function restrictTo(...roles) {
    if(!roles.includes(req.user.role)){ 
        return next(new AppError('You do not have permission to perform this action', 403));
    }
    next();
}
