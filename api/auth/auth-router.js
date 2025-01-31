const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const router = require("express").Router();
const User = require("../users/users-model");

const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { BCRYPT_ROUNDS, JWT_SECRET } = require("../secrets"); // use this secret!


router.post("/register", validateRoleName, async (req, res, next) => {

  const { username, password } = req.body;
  const { role_name } = req;
  const hash = bcrypt.hashSync(password, BCRYPT_ROUNDS);

  User.add({ username, password: hash, role_name })
    .then(newUser => {
      res.status(201).json(newUser)
    })
    .catch(next)


  // the other way..
  // try {
  //   let user = req.body;

  //   const hash = bcrypt.hashSync(user.password, BCRYPT_ROUNDS);

  //   user.password = hash;

  //   const saved = await User.add(user);

  //   res.status(201).json({
  //     user_id: saved.user_id,
  //     username: saved.username,
  //     role_name: saved.role_name,
  //   });
  // } catch (err) {
  //   next(err);
  // }


  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user_id": 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  let { username, password } = req.body;

  User.findBy({ username })
    .then(([user]) => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = generateToken(user);

        res.status(200).json({
          message: `${user.username} is back!`,
          token,
        })
      } else {
        next({ status: 401, message: 'Invalid Credentials' })
      }

    })
    .catch(next);

  // if (bcrypt.compareSync(req.body.password, req.body.user.password)) {
  //   const token = generateToken(req.user);
  //   res.status(200).json({
  //     message: `${req.user.username} is back!`,
  //     token,
  //   })

  // } else {
  //   next({ status: 401, message: 'Invalid Credentials' });
  // }

  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

function generateToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  }
  const options = {
    expiresIn: '1d',
  }
  return jwt.sign(payload, JWT_SECRET, options)
}

module.exports = router;
