const isModerator = async (req, res, next) => {
    if (req.user.role !== 'moderator' && req.user.role !== 'admin') return res.status(403)
        .json({
            success: false,
            message: "admin or moderator only can access to this route"
        });
    next();
}

module.exports = isModerator;