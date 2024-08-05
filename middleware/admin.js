const isAdmin = async (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({
        success: false,
        message: "only admin can access to this route"
    });
    next();
}

module.exports = isAdmin;