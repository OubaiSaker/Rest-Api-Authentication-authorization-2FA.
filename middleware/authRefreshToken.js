const jwt = require('jsonwebtoken');
const UserRefreshToken = require('../models/userRefreshToken');

const authRefreshToken = async function (req, res, next) {
    try {
        //check if refresh token send in request header
        const refreshToken = req.header('x-refresh-token');
        if (!refreshToken) return res.status(401).json({
            success: false,
            message: "access denied!"
        });
        //check if refresh token is valid 
        const validRefreshToken = jwt.verify(refreshToken, process.env.jwtRefreshToken);
        //check if  user refresh token exist in tokens database
        const userRefreshToken = await UserRefreshToken.findOne({
            refreshToken: refreshToken,
            user_id: validRefreshToken.user_id
        });
        if (!userRefreshToken) {
            return res.status(401).json({
                success: false,
                message: " refresh token is invalid please login "
            });
        }
        // req.userRefreshToken = userRefreshToken;
        req.user = validRefreshToken;
        next();
    }
    catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(401)
                .json({
                    success: false,
                    message: "refresh token is expired"
                });
        }
        else if (error instanceof jwt.JsonWebTokenError) {
            return res.status(401)
                .json({
                    success: false,
                    message: "refresh token is invalid"
                });
        }
        next(error)
    }
}

module.exports = authRefreshToken;