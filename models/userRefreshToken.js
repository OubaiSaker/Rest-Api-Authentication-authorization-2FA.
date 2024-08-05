const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema({
    refreshToken: {
        type: String,
        required: true
    },
    user_id: {
        type: String,
        required: true
    }
})

const UserRefreshToken = mongoose.model('userRefreshToken', refreshTokenSchema);

module.exports = UserRefreshToken