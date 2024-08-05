const express = require('express');
const app = express();

require('./start/db');
require('./start/routes')(app);

app.get('/', (req, res) => {
    res.send("Rest Api Authentication and authorization")
})

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`server lesting on port ${port}`)
});