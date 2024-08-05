module.exports = function (error, req, res, next) {
    return res.status(500).json({
        success: false,
        message: error.message
    });
}