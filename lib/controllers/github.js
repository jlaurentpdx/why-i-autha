const { Router } = require('express');
const jwt = require('jsonwebtoken');
const authenticate = require('../middleware/authenticate');
const GithubUser = require('../models/GithubUser');
const { exchangeCodeForToken, getGithubProfile } = require('../utils/github');

module.exports = Router()
  .get('/login', async (req, res) => {
    res.redirect(
      `https://github.com/login/oauth/authorize?client_id=${process.env.CLIENT_ID}&scope=user&redirect_uri=${process.env.REDIRECT_URI}`
    );
  })
  .get('/login/callback', async (req, res) => {
    /*
      TODO:
     * get code
     * exchange code for token
     * get info from github about user with token
     * get existing user if there is one
     * if not, create one
     * create jwt
     * set cookie and redirect
     */

    const accessToken = await exchangeCodeForToken(req.query.code);
    const { login, avatar_url, email } = await getGithubProfile(accessToken);

    let user = await GithubUser.findByUsername(login);

    if (!user)
      user = await GithubUser.insert({
        username: login,
        avatar: avatar_url,
        email,
      });

    const payload = jwt.sign(user.toJSON(), process.env.JWT_SECRET, {
      expiresIn: '1 day',
    });

    res.cookie(process.env.COOKIE_NAME, payload, {
      httpOnly: true,
      maxAge: 1440000, // One day in milliseconds
    });
  })
  .get('/dashboard', authenticate, async (req, res) => {
    // require req.user
    // get data about user and send it as json
    res.json(req.user);
  })
  .delete('/sessions', (req, res) => {
    res
      .clearCookie(process.env.COOKIE_NAME)
      .json({ success: true, message: 'Signed out successfully!' });
  });
