const express = require('express');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors')
const User = require('./models/User');

dotenv.config();
mongoose.connect(process.env.MONGO_URL);

const jwtSecret = process.env.TOKEN_SECRET;
const bcryptSalt = bcrypt.genSaltSync();

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(cors({
    credentials: true,
    origin: process.env.CLIENT_URL
}));

app.get('/test', (req, res) => {
    res.json('test ok');
});

app.get('/profile', (req, res) => {
    const token = req.cookies?.token;
    if (token) {
        jwt.verify(token, jwtSecret, {}, (err, userData) => {
            if (err) throw err;
            res.json(userData);
        });
    }
    else {
        res.status(401).json('no token');
    }
});

app.post('/login', async (req, res) => {
    const {username, password} = req.body;
    const foundUser = await User.findOne({username});
    if (foundUser) {
        const passOk = bcrypt.compareSync(password, foundUser.password);
        if (passOk) {
            jwt.sign({userId: foundUser._id, username}, jwtSecret, {} ,(err, token) => {
                if (err) throw err;
                res.cookie('token', token, {sameSite:'none', secure:true}).status(200).json({
                    id: foundUser._id
                });
            });
        }
        else {
            console.log(`${username} : Username or password incorrect`);
        }
    }
    else {
        console.log(`${username} : Username not registered`);
    }
});

app.post('/register', async (req, res) => {
    const {username, password} = req.body;
    const hashedPassword = bcrypt.hashSync(password, bcryptSalt);
    const createdUser = await User.create({username, password: hashedPassword});
    jwt.sign({userId: createdUser._id, username}, jwtSecret, {} ,(err, token) => {
        if (err) throw err;
        res.cookie('token', token, {sameSite:'none', secure:true}).status(201).json({
            id: createdUser._id
        });
    });
});

app.listen(4000);
