const mongoose = require('mongoose');
const uniqueValidator = require('mongoose-unique-validator');

const UserSchema = new mongoose.Schema({
    username: {type: String, unique: true},
    password: String
}, {timestamps: true});
UserSchema.plugin(uniqueValidator);

const UserModel = mongoose.model('User', UserSchema);

module.exports = UserModel;