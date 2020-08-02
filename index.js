var express = require('express')
var mongoose = require('mongoose')
const { v4: uuid } = require('uuid')
const session = require('express-session')
const FileStore = require('session-file-store')(session)
const bodyParser = require('body-parser')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const crypto = require('crypto')
var sassMiddleware = require('node-sass-middleware')
var path = require('path')
var flash = require('connect-flash')

var genRandomString = function (length) {
  return crypto
    .randomBytes(Math.ceil(length / 2))
    .toString('hex')
    .slice(0, length)
}

var sha512 = function (password, salt) {
  var hash = crypto.createHmac('sha512', salt)
  hash.update(password)
  var value = hash.digest('hex')
  return {
    salt: salt,
    passwordHash: value,
  }
}

function saltHashPassword(userpassword) {
  var salt = genRandomString(16)
  var passwordData = sha512(userpassword, salt)
  return passwordData
}

var User = mongoose.model(
  'User',
  new mongoose.Schema({
    email: String,
    password: String,
    passwordSalt: String,
  })
)

var ensureAuthenticated = function (req, res, next) {
  if (req.isAuthenticated()) return next()
  res.redirect('/login')
}

passport.use(
  new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
    User.findOne({ email: email }, (err, user) => {
      if (err) {
        return done(err)
      }
      if (!user) {
        return done(null, false, { message: 'Incorrect username.' })
      }
      var salt = user.passwordSalt
      var savedPassword = user.password
      var hash = sha512(password, salt)
      if (hash.passwordHash !== savedPassword) {
        return done(null, false, { message: 'Incorrect password.' })
      }
      return done(null, user)
    })
  })
)
passport.serializeUser((user, done) => {
  done(null, user.id)
})
passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user)
  })
})

mongoose.connect('mongodb://localhost/session-test', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})

var app = express()
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.set('view engine', 'ejs')
app.use(
  session({
    genid: (req) => {
      return uuid()
    },
    store: new FileStore(),
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
  })
)
app.use(passport.initialize())
app.use(passport.session())
app.use(
  sassMiddleware({
    src: path.join(__dirname, 'public/styles'),
    indentedSyntax: true,
    prefix: '/public',
    outputStyle: 'compressed',
    force: true,
  })
)
app.use('/public', express.static(path.join(__dirname, 'public')))
app.use(flash())

app.get('/', (req, res) => {
  res.json({
    sessionID: req.sessionID,
    req: req.session,
    auth: req.isAuthenticated(),
  })
})

app.get('/flash', function (req, res) {
  req.flash('info', 'Flash is back!')
  res.redirect('/flash-show')
})

app.get('/flash-show', function (req, res) {
  res.json(req.flash('info'))
})

app.get('/login', (req, res) => {
  res.render('index.ejs')
})

app.get('/profile', ensureAuthenticated, (req, res) => {
  res.send(`<pre>${JSON.stringify(req.session)}</pre>`)
})

app.get('/logout', function (req, res) {
  req.logout()
  res.redirect('/')
})

app.post('/register', async (req, res, next) => {
  var pass = saltHashPassword(req.body.password)
  var user = new User({
    email: req.body.email,
    password: pass.passwordHash,
    passwordSalt: pass.salt,
  })
  await user.save()
  res.json({ user })
})

app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (info) {
      return res.send(info.message)
    }
    if (err) {
      return next(err)
    }
    if (!user) {
      return res.redirect('/login')
    }
    req.login(user, (err) => {
      if (err) {
        return next(err)
      }
      return res.redirect('/')
    })
  })(req, res, next)
})

app.listen(3000, function () {
  console.log(`App started on :${3000}`)
})
