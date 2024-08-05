const mongoose = require('mongoose');

mongoose.connect(process.env.DB_URI)
    .then(() => console.log("connected to database successfully"))
    .catch(() => console.log("could not connect to database"))
