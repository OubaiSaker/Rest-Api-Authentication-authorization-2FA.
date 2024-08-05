const jwt = require('jsonwebtoken');

const authAccessToken = async function (req, res, next) {
    try {
        const accessToken = req.header('x-access-token');
        if (!accessToken) return res.status(401).json({
            success: false,
            message: "access denied!"
        });

        const validAccessToken = jwt.verify(accessToken, process.env.jwtAccessToken);

        req.user = validAccessToken;
        next();
    }
    catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(401)
                .json({
                    success: false,
                    message: "access token is expired"
                });
        }
        else if (error instanceof jwt.JsonWebTokenError) {
            return res.status(401)
                .json({
                    success: false,
                    message: "access token is invalid"
                });
        }
        next(error)
    }
}

module.exports = authAccessToken;