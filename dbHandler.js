const mongoose = require('mongoose');

function connectDb() {
    process.mongooseConnected = false; // set the flag to false initially
    mongoose.connect(process.env.MONGO_URL)
        .catch(err => {
            console.log("error on initial connection");
            console.log(err);
            console.log('Attempting to reconnect after 10 seconds...');
            setTimeout(connectDb, 10000);
        });
}

exports.connect = connectDb;