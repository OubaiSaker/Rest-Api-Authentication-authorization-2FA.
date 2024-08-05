const { User, userValidation, loginUserValidation } = require('../models/userModel');
const bcrypt = require('bcryptjs');
const UserRefreshToken = require('../models/userRefreshToken');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const crypto = require('crypto');
const NodeCache = require('node-cache');

const cache = new NodeCache();

module.exports.registerUser = async (req, res, next) => {
    try {
        //validate request 
        const { error } = userValidation(req.body);
        if (error) return res.status(400).json({
            success: false,
            message: error.details[0].message
        });
        //check if email is exist
        const isExistUser = await User.findOne({ email: req.body.email });
        if (isExistUser) return res.status(409).json({
            success: false,
            message: "user by given email already exist"
        });
        //hash password 
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);
        //create new user and save in database 
        const user = new User({
            username: req.body.username,
            email: req.body.email,
            mobile: req.body.mobile,
            password: hashedPassword
        });
        await user.save();
        //return response
        res.status(201).json({
            success: true,
            message: "user registered successfully",
            user: {
                username: user.username,
                email: user.email
            }
        });
    }
    catch (error) {
        next(error);
    }
};

module.exports.loginUser = async (req, res, next) => {
    try {
        //validate request body with joi package
        const { error } = loginUserValidation(req.body);
        if (error) return res.status(400).json({
            success: false,
            message: error.details[0].message
        });
        //check if email is valid 
        const user = await User.findOne({ email: req.body.email });
        if (!user) return res.status(401).json({
            success: false,
            message: "invalid email or password"
        });
        //check if the password is valid 
        const validPassword = await bcrypt.compare(req.body.password, user.password);
        if (!validPassword) return res.status(401).json({
            success: false,
            message: "invalid email or password"
        });
        //2 factor authentication
        if (user.enable2FA) {
            const tempToken = crypto.randomUUID();
            cache.set('tempToken:' + tempToken, user._id, 120);
            return res.status(200).json({
                success: true,
                tempToken: tempToken,
                expiresInSecond: 120
            });
        }
        else {
            //create access and refresh token
            const accessToken = user.generateAccessToken();
            const refreshToken = user.generateRefreshToken();
            //save refresh token in database
            const newRefreshToken = new UserRefreshToken({
                refreshToken: refreshToken,
                user_id: user._id
            });
            await newRefreshToken.save();
            //return respone with access and refresh tokens
            res.status(200)
                .header('x-access-Token', accessToken)
                .header('x-refresh-token', refreshToken)
                .json({
                    success: true,
                    message: "user login successfully",
                    user: {
                        username: user.username,
                        email: user.email,
                        mobile: user.mobile
                    }
                });
        }

    }
    catch (error) {
        next(error);
    }
}

module.exports.twoFactorMethod = async (req, res, next) => {
    try {
        const { tempToken, totp } = req.body;
        if (!tempToken || !totp) return res.status(422).json({
            success: false,
            message: "please fill in all fields (tempToken,totp)"
        });
        const user_id = cache.get('tempToken:' + tempToken);
        if (!user_id) return res.status(401).json({
            success: false,
            message: "the provided temporary token is expired or invalid"
        })

        const user = await User.findById({ _id: user_id });
        const verified = authenticator.check(totp, user.secret2FA);
        if (!verified) return res.status(401).json({
            success: false,
            message: "totp is expired or invalid"
        });
        //generate access and refresh token
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        const newRefreshToken = new UserRefreshToken({
            refreshToken: refreshToken,
            user_id: user._id
        });
        await newRefreshToken.save();
        //return respone with access and refresh tokens
        res.status(200)
            .header('x-access-Token', accessToken)
            .header('x-refresh-token', refreshToken)
            .json({
                success: true,
                message: "user login successfully",
                user: {
                    username: user.username,
                    email: user.email,
                    mobile: user.mobile
                }
            });
    }
    catch (error) {
        next(error);
    }
}


module.exports.genrate2fa = async (req, res, next) => {
    try {
        const user = await User.findById({ _id: req.user.user_id });
        //generate the secret 2 factor authentication
        const secret = authenticator.generateSecret();
        const uri = authenticator.keyuri(user.email, 'oubai.io', secret);
        //update secret 2fa in user data 
        await User.updateOne({ _id: user._id }, { $set: { secret2FA: secret } });
        //generate the QR Code buffer
        const qrCodeBuffer = await qrcode.toBuffer(uri, { type: 'image/png', margin: 1 });
        //set the response headers and send the QR Code buffer
        res.setHeader('Content-Disposition', 'attachment; filename=qrcode.png');
        return res.status(200).type('image/png').send(qrCodeBuffer);
    }
    catch (error) {
        next(error);
    }
}

module.exports.validate2fa = async (req, res, next) => {
    try {
        const { totp } = req.body;
        if (!totp) return res.status(422).json({
            success: false,
            message: "TOTP is required"
        });

        const user = await User.findById({ _id: req.user.user_id });
        const verified = authenticator.check(totp, user.secret2FA);
        if (!verified) return res.status(400).json({
            success: false,
            message: "totp is wrong or expired"
        });
        await User.updateOne({ _id: user._id }, { $set: { enable2FA: true } });
        return res.status(200).json({
            success: true,
            message: "you create 2FA successfully"
        });
    }
    catch (error) {
        next(error);
    }
}

module.exports.getCurrentUser = async (req, res, next) => {
    try {
        const user = await User.findById({ _id: req.user.user_id }).select('-password -_id');
        if (!user) return res.status(404).json({
            success: false,
            message: "user not found",
        });

        res.status(200).json({
            success: true,
            message: "get user successfully",
            user: user
        });
    }
    catch (error) {
        next(error);
    }
}

module.exports.getAdmin = async (req, res) => {
    res.status(200).json({
        success: true,
        message: ' you can access this route'
    });
}

module.exports.getModerator = async (req, res) => {
    res.status(200).json({
        success: true,
        message: ' you can access this route'
    });
}

module.exports.postRefreshToken = async (req, res, next) => {
    try {
        const user_id = req.user.user_id;
        const user = await User.findById({ _id: user_id });
        //create new refresh token 
        const newRefreshToken = user.generateRefreshToken();
        const newUserRefreshToken = new UserRefreshToken({
            refreshToken: newRefreshToken,
            user_id: user_id
        });
        await newUserRefreshToken.save();

        res.status(200)
            .header('x-refresh-token', newRefreshToken)
            .json({
                success: true,
                message: "refresh your token successfully"
            });
    }
    catch (error) {
        next(error);
    }
}

module.exports.logoutUser = async (req, res, next) => {
    try {
        await UserRefreshToken.deleteMany({ user_id: req.user.user_id });
        res.status(204).send();
    }
    catch (error) {
        next(error);
    }
}