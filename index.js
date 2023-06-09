require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000; //if PORT is set in environment use that, otherwise use 3000

const app = express();

const Joi = require("joi");
const { Console } = require("console");


const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));
app.set('view engine', 'ejs');

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	},
    ttl: expireTime / 1000 // ttl is in seconds
})



app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req, res) => {//
    res.render("home", {authenticated: req.session.authenticated, username: req.session.username});
  });
  
app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req,res) => {
    var color = req.query.color;

    res.send("<h1 style='color:"+color+";'>Kale Letendre</h1>");
});

app.get('/members', (req,res) => {//
    res.render('members', {authenticated: req.session.authenticated});
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req,res) => {//
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: "+email);
    }
});


app.get('/createUser', (req,res) => {//
    res.render('createUser', {exists: req.query.exists});
});

app.get('/login', (req,res) => {//
    res.render('login', {failed: req.query.failed});
});

app.post('/submitUser', async (req,res) => {//
    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;

	const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
			password: Joi.string().max(20).required(),
            email: Joi.string().email().required()
		});
	
	const validationResult = schema.validate({email, username, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/createUser");
	   return;
   }

    // check if username or email already exists
    const result = await userCollection.find({$or: [{username: username}, {email: email}]}).toArray();
    if (result.length > 0) {
        res.redirect('/createUser?exists=1');
        return;
    }
    
    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username: username, email: email, password: hashedPassword, privilage: 0});
	console.log("Inserted user");

    req.session.authenticated = true;
    req.session.email = email;
    req.session.username = username;
    req.session.privilage = false;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/');
});

app.post('/loggingin', async (req,res) => {//
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().max(30).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login?failed=1");
	   return;
	}

	const result = await userCollection.find({email: email}).project({email: 1, password: 1, _id: 1}).toArray();
    // get the username associated with the email
    req.session.username = result[0].username;

	console.log(result);
	if (result.length != 1) {
        res.redirect("/login?failed=1");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.email = email;
        req.session.privilage = result[0].privilage;
        req.session.username = result[0].username;
		req.session.cookie.maxAge = expireTime;
		res.redirect('/');
		return;
	}
	else {
		res.redirect("/login?failed=1")
		return;
	}
});

app.get('/loggedin', (req,res) => {//
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    var html = `<h1>Hello ${req.session.username}</h1>
                <a href='/logout'>logout</a>`;
    res.send(html);
});

app.get('/logout', (req,res) => {//
	// delete all the cookies
    req.session.destroy();

    res.redirect('/');
});

app.get('/admin', async (req,res) => {//
    // pull the session user from the database
    var user = await userCollection.findOne({email: req.session.email});
    req.session.privilage = user.privilage;
    
    console.log(req.session);
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    if (user.privilage) {
        // get array of all users
        var users = await userCollection.find().toArray();
        res.render('users', {users: users});
    } else {
        res.render('403');
    }
});

app.get('/promote', async (req,res) => {//
    // ensure user is logged in and has admin privilages
    if (!req.session.authenticated || !req.session.privilage) {
        res.render('403');
    } else {
        var email = req.query.email;
        userCollection.updateOne({email: email}, {$set: {privilage: 1}});
        res.redirect('/admin');
    }
});

app.get('/demote', async (req,res) => {//
    // ensure user is logged in and has admin privilages
    if (!req.session.authenticated || !req.session.privilage) {
        res.render('403');
    } else{
        var email = req.query.email;
        userCollection.updateOne({email: email}, {$set: {privilage: 0}});
        res.redirect('/admin');
    }
});


app.get("*", function(req, res) {
    res.status(404);
    res.render('404');
});

app.listen(port, () => {
	console.log("Node application listening on port "+port);
});