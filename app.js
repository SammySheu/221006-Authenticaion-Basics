/////// app.js

const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs") ;
const Schema = mongoose.Schema;

const mongoDb = "mongodb://127.0.0.1:27017/authentication-practice";
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
    hashedPassword: { type: String}
  })
);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

// Function One
passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne({ username: username }, (err, user) => {
      if (err) {
        return done(err);
      }
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      if (user.hashedPassword !== password){
        bcrypt.compare(password, user.hashedPassword, (err, res) => {
          if (res) {
            // passwords match! log user in
            return done(null, user)
          } else {
            // passwords do not match!
            return done(null, false, { message: "Incorrect password" })
          }
        })
        // return done(null, false, { message: "Incorrect password" });
      }
      // return done(null, user);
    });
  })
);

// Function Two
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

// Function Three
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

// Middleware functions are functions that take the req and res objects, manipulate them,
// and pass them on through the rest of the app.
// If we store data in locals object, we can access them throughout our entire app. 
// Below code are supplemental. 
app.use(function(req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

app.use(express.urlencoded({ extended: false }));

// If user.name & user.password mathced the data in db,
// passport's middleware then creates a session cookie that gets stored in the user’s browser. 
// We can, therefore, access in all future requests to see whether or not that user is logged in.

// req.user = user (if user match the data in db)
// req.user = undefine (if user doesn't match the data in db)

app.get("/", (req, res) => {
  res.render("index", { user: req.user });
});
app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.get("/log-out", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});


app.post("/sign-up", (req, res, next) => {
    bcrypt.hash(req.body.password, 10, (error, hashedPassword) => {
      const user = new User({
        username: req.body.username,
        password: req.body.password,
        hashedPassword: hashedPassword
      }).save(err => {
        if (err) {
          return next(err);
        }
        res.redirect("/");
      });
    }) ;
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/"
  })
);

app.listen(3000, () => console.log("app listening on port 3000!"));
