require('dotenv').config();
require('./config/database').connect();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const auth = require('./middleware/auth');

// console.log('process.env', process.env);
const app = express();

app.use(express.json());

// Logic goes here

// importing user context
const User = require('./model/user');

// Register
app.post('/register', async (req, res) => {
  // our register logic goes here...
  try {
    // 1 Get user input. the key is the same with user model
    const { first_name, last_name, password, email } = req.body;
    // 2 Validate user input.
    if (!(email && password && first_name && last_name)) {
      res.status(400).send('All input is required');
    }
    // 3 Validate if the user already exists.
    const oldUser = await User.findOne({ email });

    if (oldUser) {
      //https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Status/409
      return res.status(409).send('User Already Exist. Please Login');
    }
    // 4 Encrypt the user password.
    let encryptedPassword = await bcrypt.hash(password, 10);
    // 5 Create a user in our database.
    const user = await User.create({
      first_name,
      last_name,
      email: email.toLowerCase().trim(),
      password: encryptedPassword,
    });

    //create token
    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.TOKEN_KEY,
      {
        expiresIn: '2h',
      }
    );
    // save user token
    user.token = token;
    // 6 And finally, create a signed JWT token.
    // return new user
    console.log('user', user);
    res.status(201).json(user);
  } catch (error) {}
});

// Login
app.post('/login', async (req, res) => {
  try {
    // Get user input
    const { email, password } = req.body;

    // Validate user input
    if (!(email && password)) {
      res.status(400).send('All input is required');
    }
    // Validate if user exist in our database
    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      // Create token
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.TOKEN_KEY,
        {
          expiresIn: '2h',
        }
      );

      // save user token
      user.token = token;

      // user
      res.status(200).json(user);
    }
    res.status(400).send('Invalid Credentials');
  } catch (err) {
    console.log(err);
  }
});

//Welcome use auth middleware
//不加auth 直接就会返回 加了就会要求传入token
app.post('/welcome', auth, (req, res) => {
  res.status(200).send('Welcome 🙌 ');
});

module.exports = app;
