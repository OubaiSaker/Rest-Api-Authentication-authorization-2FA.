const express = require('express');

const userRouter = require('../routes/userRoute');
const errorHandler = require('../middleware/errorHandler');

module.exports = function (app) {
    app.use(express.json());
    app.use('/api/users', userRouter);
    app.use(errorHandler);
};

