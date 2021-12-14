const express = ('express')
const bcrypt = ('bcrypt')
const router = express.Router()
const User = ('..users/users-model')
const { restricted,
        checkPasswordLength, 
        checkUsernameExists, 
        checkUsernameFree } = require('./auth-middleware')
// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!


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
router.post('/register', async (req, res, next) => {
  try {
    const { username, password} = req.body
    const newUser = {
      username,
      password: bcrypt,hashSync(password, 8)
    }
    const created = await User.add(newUser)
  } catch (err){
    next(err)
  }
})

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
router.post('/login', async (req, res, next) => {
  try{
      const { username, password } = req.body
      const [userFromDb] = await User.findBy({ username })
      if(!userFromDb) {
        return next ({status: 401, message: "Invalid credentials"})
      }
      req.session.user = userFromDb
      res.json({ message: `Welcome ${username}!`})

  } catch (err) {
    next(err)
  }
})

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
router.get('/logout', async (req, res, next)=> {
  try{
    if(req.session.user) {
      req.session.destroy((err) => {
        if (err){
          res.json('')
        }
      })
    }
  }
})
 
// Don't forget to add the router to the `exports` object so it can be required in other modules
