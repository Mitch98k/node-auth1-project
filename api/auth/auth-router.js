// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require('express');
const bcrypt = require('bcryptjs');

const Users = require('../users/users-model');
const {checkUsernameFree, checkUsernameExists, checkPasswordLength} = require('./auth-middleware');

const router = express.Router();

router.post('/api/auth/register', checkUsernameFree, checkPasswordLength, async (req, res) => {
  const {username, password} = req.body;
  const hash = bcrypt.hashSync(password, 9);
  try {
    const user = await Users.add({ username, password: hash });
    res.status(201).json(user);
  } catch(err) {
    res.status(500).json({ message: "There was an error in registering you" });
  }
});
/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post('/api/auth/login', checkUsernameExists, async (req, res) => {
  const {username, password} = req.body;
  const user = Users.findBy({username});
  try {
    if (user && bcrypt.compareSync(password, user.password)) {
      req.session.user = user;
      res.status(200).json({ message: `Welcome ${username}!` });
    } else {
      res.status(401).json({ message: "invalid credentials" });
    }
  } catch(err) {
    console.log("This. Is. PASSWORD!!!", password);
    res.status(500).json({ message: "There was an error logging you in", error: err.message });
  }
});
/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

router.get('/api/auth/logout', async (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        res.json({ message: "cannot log out" });
      } else {
        res.json({ message: "logged out" });
      }
    });
  } else {
    res.json({ message: "no session" });
  }
});
/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

 module.exports = router;
// Don't forget to add the router to the `exports` object so it can be required in other modules
