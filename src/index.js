const express = require('express')
const jwt = require('jsonwebtoken')
const morgan = require('morgan');
const passport = require('passport');
const bcrypt = require('bcrypt');
const passportJWT = require("passport-jwt");
const LocalStrategy = require('passport-local').Strategy;

const app = express();
const router = express.Router();

const ExtractJWT = passportJWT.ExtractJwt;
const JWTStrategy   = passportJWT.Strategy;

const Users = [
  {
      "id": 1,
      "username": "mturchyn",
      "password": "$2b$10$4EDSoxgY2HA46Ytes6NWme6ufPYxQJmcqMvyQG.PSY2l2lINxI2Si",
      "salt": "$2b$10$4EDSoxgY2HA46Ytes6NWme"
  },
  {
      "id": 2,
      "username": "someone",
      "password": "$2b$10$GpDC0H7QFpjHEK63hstubejaCIJaQPZm1FtHeGk3KUAS3MpTiqZw2",
      "salt": "$2b$10$GpDC0H7QFpjHEK63hstube"
  }
];

app.use(express.json())
app.use(morgan(':method :url :status :res[content-length] - :response-time ms'));

app.use((req, res, next) => {
  console.log(req.path);
  next();
});

let UserModel = {
  findOneById: (id) => {
    return new Promise((resolve, reject) => {
      let res = Users.filter((user)=> user.id === id)
      resolve(res[0])
    })
  },
  findOne: ({username, password}) => {
    return new Promise((resolve, reject)=> {
      let res = Users.filter((user) => user.username === username)
      console.log(res, password, res[0]["password"]);
      bcrypt.compare(password, res[0]["password"], (err, result)=>{
        if(err) {
          reject(err);
        } else if (result) {
          resolve(res[0])
        }
      })
    })
  }
}

passport.use(new JWTStrategy({
    jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey   : 'your_jwt_secret'
  },
  function (jwtPayload, cb) {
    console.log('smth1')
  //find the user in db if needed
  return UserModel.findOneById(jwtPayload.id)
      .then(user => {
          return cb(null, user);
      })
      .catch(err => {
          return cb(err);
      });
  }
));

passport.use(new LocalStrategy({
  usernameField: 'username',
  passwordField: 'password'
},
function (username, password, cb) {
  // console.log(username, password)
  console.log('smth2')
  //Assume there is a DB module pproviding a global UserModel
  return UserModel.findOne({username, password})
      .then(user => {
          if (!user) {
              return cb(null, false, {message: 'Incorrect email or password.'});
          }

          return cb(null, user, {
              message: 'Logged In Successfully'
          });
      })
      .catch(err => {
          return cb(err);
      });
}
));

router.post('/login', (req, res, next) => {
  passport.authenticate('local', {session: false}, (err, user, info) => {
    console.log('login')
    console.log(err);
    if (err || !user) {
        return res.status(400).json({
            message: info ? info.message : 'Login failed',
            user   : user
        });
    }

    req.login(user, {session: false}, (err) => {
        if (err) {
            res.status(403).send(err);
        }

        const token = jwt.sign(user, 'your_jwt_secret');

        return res.status(200).json({user, token});
    });
  })
    (req, res);
});

router.get('/private', passport.authenticate('jwt', {session: false}), (req, res, next) => {
  res.send(req.user);
})

router.post('/register', (req, res) => {
  const {
    username,
    password,
    firstName,
    lastName
  } = req.body;

  if (username && password) {
    bcrypt.genSalt(10, (err, salt) => {
      if (err) {
        res.sendStatus(500);
      }
      bcrypt.hash(password, salt, (err, hash) => {
        if (err) {
          res.sendStatus(500);
        }

        let newUser = {
          id: Users.length + 1,
          username: username,
          password: hash,
          salt: salt
        };

        Users.push(newUser)
        res.status(201).json(Users)
      })
    })
  } else if (!username || !password) {
    res.sendStatus(422);
  } else {
    res.sendStatus(400);
  }
})


app.use('/auth', router);

app.listen(3000, () => {
  console.log('server running');
});
