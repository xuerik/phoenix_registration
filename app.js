// Node.js Modules
var express = require('express');
var path = require('path');
var favicon = require('static-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session')
var mongoose = require('mongoose');
var nodemailer = require('nodemailer');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var bcrypt = require('bcrypt-nodejs');
var async = require('async');
var crypto = require('crypto');
var flash = require('express-flash');


// Create MongoDB Schema.
var userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    firstname: { type: String, required: true, unique: false},
    lastname: { type: String, required: true, unique: false},
    resetPasswordToken: String,
    resetPasswordExpires: Date
});

// Create Mongoose hash method.
userSchema.pre('save', function(next) {
    var user = this;
    var SALT_FACTOR = 5;

    if (!user.isModified('password')) return next();

    bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
        if (err) return next(err);

        bcrypt.hash(user.password, salt, null, function(err, hash) {
            if (err) return next(err);
            user.password = hash;
            next();
        });
    });
});

// Mongoose instance method for password verification during sign-in.
userSchema.methods.comparePassword = function(candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch);
    });
};

// Convert userSchema into a model in order to use it.
var User = mongoose.model('User', userSchema);

// Local Strategy.
passport.use(new LocalStrategy(function(username, password, done) {
    User.findOne({ username: username }, function(err, user) {
        if (err) return done(err);
        if (!user) return done(null, false, { message: 'Incorrect username.' });
        user.comparePassword(password, function(err, isMatch) {
            if (isMatch) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'Incorrect password.' });
            }
        });
    });
}));

// Stay logged-in between different pages.
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

var app = express();
// Connect to MongoDB database.
mongoose.connect('mongodb://heroku_4nllv41c:k76l6aqj61mgq4rcje3u0prrbo@ds061405.mongolab.com:61405/heroku_4nllv41c');


// Middleware
app.set('port', process.env.PORT || 3000);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.use(favicon());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());
app.use(session({ secret: 'session secret key' }));
app.use(flash());
// Add Passport middleware.
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));


// Routes
app.get('/', function(req, res) {
  res.render('index', {
      title: 'Express',
      user: req.user
  });
});

app.get('/login', function(req, res) {
    res.render('login', {
        user: req.user
    });
});

app.post('/login', function(req, res, next) {
    passport.authenticate('local', function(err, user, info) {
        if (err) return next(err)
        if (!user) {
            return res.redirect('/login')
        }
        req.logIn(user, function(err) {
            if (err) return next(err);
            return res.redirect('/');
        });
    })(req, res, next);
});

app.get('/signup', function(req, res) {
    res.render('signup', {
        user: req.user
    });
});

app.post('/signup', function(req, res) {
    var user = new User({
        password: req.body.password
    });

    user.save(function(err) {
        req.logIn(user, function(err) {
            res.redirect('/');
        });
    });
});

app.get('/createcompany', function(req, res) {
    res.render('createcompany', {
        user: req.user
    });
});

app.post('/createcompany', function(req, res) {
    var user = new User({
        username: req.body.username,
        email: req.body.email,
        password: req.body.password
    });

    user.save(function (err) {
        req.logIn(user, function (err) {
            res.redirect('/');
        });
    });
});

app.get('/visitorform', function(req, res) {
    res.render('visitorform', {
        user: req.user
    });
});

app.get('/theme', function(req, res) {
    res.render('theme', {
        user: req.user
    });
});

app.get('/logo.jpg', function(req, res) {
    res.render('logo.jpg', {
        user: req.user
    });
});

app.get('/theme', function(req, res) {
    res.render('theme', {
        user: req.user
    });
});


app.get('/employees', function(req, res) {
    res.render('employees', {
        user: req.user
    });
});

app.get('/logout', function(req, res){
    req.logout();
    res.redirect('/');
});

app.get('/forgot', function(req, res) {
    res.render('forgot', {
        user: req.user
    });
});

app.post('/forgot', function(req, res, next) {
    async.waterfall([
        function(done) {
            crypto.randomBytes(20, function(err, buf) {
                var token = buf.toString('hex');
                done(err, token);
            });
        },
        function(token, done) {
            User.findOne({ email: req.body.email }, function(err, user) {
                if (!user) {
                    req.flash('error', 'No account with that email address exists.');
                    return res.redirect('/forgot');
                }

                user.resetPasswordToken = token;
                user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

                user.save(function(err) {
                    done(err, token, user);
                });
            });
        },
        function(token, user, done) {
            var smtpTransport = nodemailer.createTransport('smtps://postmaster@sandbox4bb0b551d7c0472baef548facaf35cf5.mailgun.org:856f570c9a6e001349219f34b59db943@smtp.mailgun.org');
            //var smtpTransport = nodemailer.createTransport('SMTP', {
            //    service: 'Mailgun',
            //    auth: {
            //        user: 'postmaster@sandbox4bb0b551d7c0472baef548facaf35cf5.mailgun.org',
            //        pass: '856f570c9a6e001349219f34b59db943'
            //    }
            //});
            var mailOptions = {
                to: user.email,
                from: 'passwordreset@demo.com',
                subject: 'Node.js Password Reset',
                text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
                'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                'http://' + req.headers.host + '/reset/' + token + '\n\n' +
                'If you did not request this, please ignore this email and your password will remain unchanged.\n'
            };
            smtpTransport.sendMail(mailOptions, function(err, info) {
                req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
                done(err, 'done');
            });
        }
    ], function(err) {
        if (err) return next(err);
        res.redirect('/forgot');
    });
});

app.get('/reset/:token', function(req, res) {
    User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
            req.flash('error', 'Password reset token is invalid or has expired.');
            return res.redirect('/forgot');
        }
        res.render('reset', {
            user: req.user
        });
    });
});

app.post('/reset/:token', function(req, res) {
    async.waterfall([
        function(done) {
            User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
                if (!user) {
                    req.flash('error', 'Password reset token is invalid or has expired.');
                    return res.redirect('back');
                }

                user.password = req.body.password;
                user.resetPasswordToken = undefined;
                user.resetPasswordExpires = undefined;

                user.save(function(err) {
                    req.logIn(user, function(err) {
                        done(err, user);
                    });
                });
            });
        },
        function(user, done) {
            var smtpTransport = nodemailer.createTransport('smtps://postmaster@sandbox4bb0b551d7c0472baef548facaf35cf5.mailgun.org:856f570c9a6e001349219f34b59db943@smtp.mailgun.org');
            //var smtpTransport = nodemailer.createTransport('SMTP', {
            //    service: 'Mailgun',
            //    auth: {
            //        user: 'postmaster@sandbox4bb0b551d7c0472baef548facaf35cf5.mailgun.org',
            //        pass: '856f570c9a6e001349219f34b59db943'
            //    }
            //});
            var mailOptions = {
                to: user.email,
                from: 'passwordreset@demo.com',
                subject: 'Your password has been changed',
                text: 'Hello,\n\n' +
                'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
            };
            smtpTransport.sendMail(mailOptions, function(err, info) {
                req.flash('success', 'Success! Your password has been changed.');
                done(err);
            });
        }
    ], function(err) {
        res.redirect('/');
    });
});


app.listen(app.get('port'), function() {
  console.log('Express server listening on port ' + app.get('port'));
});