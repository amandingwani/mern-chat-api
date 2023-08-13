const express = require('express');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors')
const User = require('./models/User');
const Message = require('./models/Message');
const ws = require('ws');
const dbCheckStatus = require('./middleware/dbCheckStatus.js')
const dbHandler = require('./dbHandler.js');

dotenv.config();

mongoose.connection
    .on('error', err => {
      console.error(err);
    })
    .on('connected', err => {
        process.mongooseConnected = true;
      	console.log(`DB connected`);
    })
    .on('disconnected', () => {
        // No need to try reconnecting here as it automatically attempts reconnection
        process.mongooseConnected = false;
        console.log(`DB disconnected`);
		notifyAllAboutDbConnectionStatus('DB disconnected');
    });
dbHandler.connect();

const jwtSecret = process.env.TOKEN_SECRET;
const bcryptSalt = bcrypt.genSaltSync();

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(cors({
    credentials: true,
    origin: process.env.CLIENT_URL
}));

async function getUserDataFromReq(req) {
    return new Promise((resolve, reject) => {
        const token = req.cookies?.token;
		try {
			if (token) {
				jwt.verify(token, jwtSecret, {}, (err, userData) => {
					if (err) throw err;
					resolve(userData);
				});
			}
			else {
				reject('no token');
			}
		} catch (error) {
			reject('Invalid token');
		}
    }) ;
}

app.get('/test', (req, res) => {
    res.json({
		test: 'ok',
		db: (process.mongooseConnected) ? 'connected' : 'disconnected'
	});
});

app.get('/messages/:userId', dbCheckStatus, async (req, res) => {
    const {userId: selectedUserId} = req.params; // userId of the user selected in the frontend
	try {
		const ourUserData = await getUserDataFromReq(req); // userData of the user making the request
		const ourUserId = ourUserData.userId;

		const messages = await Message.find({
			sender: {$in:[ourUserId, selectedUserId]},
			recipient: {$in:[ourUserId, selectedUserId]}
		}).sort({createdAt: 1}).lean();

		res.json(messages);

	} catch (error) {
		if (error === 'no token') {
			res.status(401).json('Unauthorized');
		}
		else {
			console.log(error);
			res.json({error: 'db error'})
		}
	}
});

// finds all friends (as User objects) of a User
async function findFriends(userId) {
	return new Promise(async (resolve, reject) => {
		try {
			// find reqUser doc
			const reqUser = await User.findOne({ _id: userId }).lean();
		
			const friendsIds = reqUser.friends;
			// find all user objects with id in friends
			const friends = await User.find({
				_id: {$in: friendsIds}
			}, '_id username').lean();
			// lean() converts mongoose document to javascript object so we can add a new field
		
			resolve(friends);
		} catch (error) {
			reject('db error');
		}
	});
}

// endpoint to get all friends of a user
app.get('/friends', dbCheckStatus, async (req, res) => {
	try {
		const reqUserData = await getUserDataFromReq(req); // userData of the user making the request
		const reqUserId = reqUserData.userId;

		const friends = await findFriends(reqUserId);
		// for every friend, add current online status
		friends.map(friend => {
			let onlineStatus = false;
			let result = [...wss.clients].filter(c => {
				return c.userId === friend._id.toString();
			});
			if (result.length !== 0) {
				onlineStatus = true;
			}
			friend['online'] = onlineStatus;
		})
		res.json(friends);

	} catch (error) {
		if (error === 'no token' || error === 'Invalid token') {
			res.status(401).json('Unauthorized');
		}
		else {
			// console.log(error);
			res.json({error: 'db error'});
		}
	}
});

app.get('/profile', (req, res) => {
    const token = req.cookies?.token;
	try {
		if (token) {
			jwt.verify(token, jwtSecret, {}, (err, userData) => {
				if (err) throw err;
				res.json(userData);
			});
		}
		else {
			res.status(401).json('no token');
		}
	} catch (error) {
		res.status(401).json('Unauthorized');
	}
});

app.post('/addFriend/:username', dbCheckStatus, async (req, res) => {
    const {username} = req.params; // userId of the user selected in the frontend
	if (!username) {
		res.json({error: 'Please enter a valid username!'});
	}

	try {
		const reqUserData = await getUserDataFromReq(req); // userData of the user making the request
		const reqUserId = reqUserData.userId;

		// check if friends username is not the same as reqUser name
		if (username === reqUserData.username){
			res.json({error: "Please enter your friend's username!"});
		}
		else {
			// find reqUser doc
			const reqUser = await User.findOne({ _id: reqUserId });
	
			// find friend doc
			const friendUser = await User.findOne({username});
			if (friendUser) {
				// check if already friends
				if (reqUser.friends.includes(friendUser._id)) {
					res.json({error: 'Friend already added!'});
				}
				else {
					// add friendUser to reqUser friends and vice versa
					// Append items to `friends`
					reqUser.friends.push(friendUser._id);
					// Update document
					await reqUser.save();
		
					// Append items to `friends`
					friendUser.friends.push(reqUser._id);
					// Update document
					await friendUser.save();

					// respond with the added friend details along with online status
					let onlineStatus = false;
					let result = [...wss.clients].filter(c => {
						return c.userId === friendUser._id.toString();
					});
					if (result.length !== 0) {
						onlineStatus = true;

						// inform the friend that reqUser added you as friend
						result.forEach(client => {
							client.send(JSON.stringify({addFriend: {_id: reqUser._id, username: reqUser.username, online: true}}));
						});
					}
					
					res.json({msg: 'Friend added!', friend: {_id: friendUser._id, username: friendUser.username, online: onlineStatus}});
				}
			}
			else {
				res.json({error: 'Username does not exist!'});
			}
		}
	} catch (error) {
		if (error === 'no token') {
			res.status(401).json('Unauthorized');
		}
		else {
			console.log(error);
			res.json({error: 'Server error'})
		}
	}
});

app.post('/login', dbCheckStatus, async (req, res) => {
    const {username, password} = req.body;
	if (!username) {
		res.json({msg: 'Please enter a username'});
	}
	else if (!password) {
		res.json({msg: 'Please enter a password'});
	}
	else {
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
				res.json({msg: 'Incorrect username or password'});
			}
		}
		else {
			// console.log(`${username} : Username not registered`);
			res.json({msg: 'Incorrect username or password'});
		}
	}
});

app.post('/logout', (req, res) => {
    res.cookie('token', '', {sameSite:'none', secure:true}).status(200).json('logout ok');
});

app.post('/register', dbCheckStatus, async (req, res) => {
    const {username, password} = req.body;
	if (!username) {
		res.json({msg: 'Please enter a username'});
	}
	else if (!password) {
		res.json({msg: 'Please enter a password'});
	}
	else {
		const hashedPassword = bcrypt.hashSync(password, bcryptSalt);
		try {
			const createdUser = await User.create({username, password: hashedPassword});
			jwt.sign({userId: createdUser._id, username}, jwtSecret, {} ,(err, token) => {
				if (err) throw err;
				res.cookie('token', token, {sameSite:'none', secure:true}).status(201).json({
					id: createdUser._id
				});
			});
		} catch (error) {
			console.log(error);
			res.json({msg: 'Username is already taken'});
		}
	}
});

const server = app.listen(4000);

const wss = new ws.WebSocketServer({server});
wss.on('connection', (connection, req) => {

    async function notifyAllFriends(status) {
		// get all friends of the connection
		try {
			const friends = await findFriends(connection.userId);

			// find all online friends amongst connections
			let onlineFriends = [];
			friends.map(friend => {
				let result = [...wss.clients].filter(c => {
					return c.userId === friend._id.toString();
				});
				if (result.length !== 0) {
					onlineFriends.push(...result);
				}
			});
			
			// notify all online friends of the new user that its online(true) or offline(false)
			onlineFriends.forEach(client => {
				client.send(JSON.stringify({
					status: {userId: connection.userId, username: connection.username, status: status}
				}));
			});
		} catch (error) {
			console.log(error);
		}
    }

    connection.on('error', console.error);

    // Extract client info from cookie
    const cookie = (req.headers.cookie);
    if (cookie) {
		try {
			const token = cookie.split('=')[1];
			jwt.verify(token, jwtSecret, {}, (err, userData) => {
				if (err) throw err;
				const {userId, username} = userData;
				connection.userId = userId;
				connection.username = username; 
			});
			console.log('A client connected: ', connection.userId, connection.username);
			notifyAllFriends(true); // online -> true
		} catch (error) {
			console.log('WS: Invalid token');
			connection.terminate();
		}
    }
	else {
		console.log('WS: No cookie');
		connection.terminate();
	}

    connection.on('close', () => {
        console.log(connection.userId, 'disconnected');
        notifyAllFriends(false); // offline -> false
        connection.terminate();
    })
    
    // setting callback for message from connection
    connection.on('message', async (rawData) => {
        const msgString = rawData.toString();
        const {recipient, text} = JSON.parse(msgString);
        // console.log(text);
        if (recipient && text) {
			try {
				// save msg to db
				const msgDocument = await Message.create({
					sender: connection.userId,
					recipient: recipient,
					text: text
				});
	
				// send the message to recipient (there can be multiple clients(phone, laptop etc) for the same recipient)
				[...wss.clients]
					.filter(c => c.userId === recipient)
					.forEach(c => c.send(JSON.stringify({
						_id: msgDocument._id,
						sender: connection.userId,
						recipient,
						text
					})));
			} catch (error) {
				console.log(error);
			}
        }        
    });
});

function notifyAllAboutDbConnectionStatus(status) {
	wss.clients.forEach(client => {
		client.send(JSON.stringify({
			error: status
		}));
	});
}