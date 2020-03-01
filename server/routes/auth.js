const router = require('express').Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const { check, validationResult, body } = require('express-validator');
const secretJWT = require('../configs/secret').secret;
const sgMail = require('@sendgrid/mail');

require('dotenv').config();

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Login
router.post(
  '/login',
  [
    check('username')
      .not()
      .isEmpty()
      .trim()
      .escape(),
    check('password').isLength({ min: 6 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }

    try {
      let user = await User.findOne({ username: req.body.username });

      if (!user) {
        return res.status(404).json({
          success: false,
          msg: 'Account is not exist'
        });
      }

      let validPassword = await bcrypt.compare(req.body.password, user.password);

      if (!validPassword) {
        return res.status(403).json({
          success: false,
          msg: 'Username or Password incorrect'
        });
      }

      let token = jwt.sign(
        {
          user: user
        },
        secretJWT
      );

      return res.json({
        success: true,
        fullname: user.fullname,
        msg: 'Login success',
        token: token,
        role: user.role
      });
    } catch (error) {
      if (err) {
        return res.status(500).json({
          success: false,
          msg: 'Internal Server Error'
        });
      }
    }
  }
);

router.post(
  '/register',
  [
    body('username')
      .not()
      .isEmpty()
      .trim()
      .escape(),
    body('email').isEmail(),
    body('password')
      .not()
      .isEmpty()
      .trim()
      .isLength({ min: 6 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }

    try {
      let user = await User.findOne({ username: req.body.username });

      if (user) {
        return res.status(409).json({
          success: false,
          msg: 'Account already exist'
        });
      }

      let newUser = new User({
        username: req.body.username,
        password: req.body.password,
        email: req.body.email
      });

      newUser.save();

      return res.json({
        success: true,
        msg: 'Register success'
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        msg: 'Internal Server Error'
      });
    }
  }
);

router.post(
  '/recover',
  [
    check('email')
      .isEmail()
      .withMessage('Enter a valid email address')
  ],
  async (req, res) => {
    try {
      let user = await User.findOne({ email: req.body.email });

      if (!user) {
        return res.status(404).json({
          msg: 'User does not exists'
        });
      }

      //Generate and set password reset token
      user.generatePasswordReset();

      await user.save();

      let link = 'http://' + req.headers.host + '/auth/reset/' + user.resetPasswordToken;
      console.log(link);

      const mailOptions = {
        to: user.email,
        from: process.env.FROM_EMAIL,
        subject: 'Password change request',
        text: `Hi ${user.username} \n 
            Please click on the following link ${link} to reset your password. \n\n 
            If you did not request this, please ignore this email and your password will remain unchanged.\n`
      };

      await sgMail.send(mailOptions);

      return res
        .status(200)
        .json({ message: 'A reset email has been sent to ' + user.email + '.' });
    } catch (error) {
      return res.status(500).json({
        msg: 'Internal server error'
      });
    }
  }
);

router.get('/reset/:token', async (req, res) => {
  try {
    const user = await User.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(401).json({ message: 'Password reset token is invalid or has expired.' });
    }

    return res.json({
      msg: user
    });
  } catch (error) {
    return res.status(500).json({
      msg: 'Internal server error'
    });
  }
});

router.post(
  '/reset/:token',
  check('password')
    .not()
    .isEmpty()
    .isLength({ min: 6 })
    .withMessage('Must be at least 6 chars long'),
  check('confirmPassword', 'Passwords do not match').custom(
    (value, { req }) => value === req.body.password
  ),
  async (req, res) => {
    try {
      let user = await User.findOne({
        resetPasswordToken: req.params.token,
        resetPasswordExpires: { $gt: Date.now() }
      });

      if (!user) {
        return res.status(401).json({ message: 'Password reset token is invalid or has expired.' });
      }

      user.password = req.body.password;
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;

      await user.save();

      const mailOptions = {
        to: user.email,
        from: process.env.FROM_EMAIL,
        subject: 'Your password has been changed',
        text: `Hi ${user.username} \n 
              This is a confirmation that the password for your account ${user.email} has just been changed.\n`
      };

      await sgMail.send(mailOptions);
      res.status(200).json({ message: 'Your password has been updated.' });
    } catch (error) {
      return res.status(500).json({
        msg: 'Internal server error'
      });
    }
  }
);

module.exports = router;
