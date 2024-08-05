const mongoose = require('mongoose');
const Joi = require('joi');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    mobile: {
        type: String,
        minlength: 10,
        maxlength: 10,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        default: 'member'
    },
    enable2FA: {
        type: Boolean,
        default: false
    },
    secret2FA: {
        type: String,
        default: null
    }
});
//generate user register token 
userSchema.methods.generateAccessToken = function () {
    const accessToken = jwt.sign({
        user_id: this._id,
        username: this.username,
        role: this.role
    },
        process.env.jwtAccessToken,
        { subject: "access token ", expiresIn: "1m" });
    return accessToken;
}

userSchema.methods.generateRefreshToken = function () {
    const refreshToken = jwt.sign({
        user_id: this._id,
        username: this.username,
        role: this.role,
    },
        process.env.jwtRefreshToken,
        { subject: "refresh token ", expiresIn: "1w" });
    return refreshToken;
}

const User = mongoose.model('user', userSchema);

function userValidation(user) {
    const schema = Joi.object({
        username: Joi.string()
            .alphanum()
            .min(3)
            .max(30)
            .required(),
        email: Joi.string().email().required(),
        mobile: Joi.string().min(10).max(10).required(),
        password: Joi.string().min(8).required()
    });

    return schema.validate(user);
}

function loginUserValidation(user) {
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(8).required()
    });

    return schema.validate(user)
}

module.exports = {
    User,
    userValidation,
    loginUserValidation
}