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

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req,res) => {
    if (!req.session.authenticated) {
        var html = `<h1>Welcome</h1>
        <a href='/createUser'>sign up</a><br>
        <a href='/login'>login</a><br>
        `;
    }
    else {
        // get username from database
        var html = `<h1>Welcome ${req.session.username}</h1>
        <a href='/members'>members</a><br>
        <a href='/logout'>sign out</a><br>
        `;
    }
    res.send(html);
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

app.get('/members', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    }
    else {
        // random number between 1 and 10
        var randomNumber = Math.floor(Math.random() * 3) + 1;
        var html = `<h1>check out this secret information</h1>
        <a href='/'>home</a>
        <a href='/logout'>sign out</a>
        <br>
        <img src='/fluffy${randomNumber}.gif' style='width: 300px;'>`;
        res.send(html);
    }
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

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: "+email);
    }
});


app.get('/createUser', (req,res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    if (req.query.exists) {
        html += "<br> username or email already exists";
    }
    res.send(html);
});

app.get('/login', (req,res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    if (req.query.failed) {
        html += "<br> login failed";
    }
    res.send(html);
});

app.post('/submitUser', async (req,res) => {
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
	
	await userCollection.insertOne({username: username, email: email, password: hashedPassword});
	console.log("Inserted user");

    var html = "successfully created user";
    res.send(html);
});

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
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
		req.session.cookie.maxAge = expireTime;

		res.redirect('/');
		return;
	}
	else {
		res.redirect("/login?failed=1")
		return;
	}
});

app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    var html = `<h1>Hello ${req.session.username}</h1>
                <a href='/logout'>logout</a>`;
    res.send(html);
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});


app.get('/cat/:id', (req,res) => {

    var cat = req.params.id;

    if (cat == 1) {
        res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
    }
    else if (cat == 2) {
        res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
    }
    else {
        res.send("Invalid cat id: "+cat);
    }
});


app.use(express.static(__dirname + "/public"));

// app.get("*", (req,res) => {
// 	res.status(404);
// 	res.send("Page not found - 404");
// })
// 404 page
app.get("*", function(req, res) {
    res.redirect("/does_not_exist");
});

app.get('/does_not_exist', (req,res) => {
    res.status(404);
    var html = `
            <style type="text/css">
                body {
                    background-color: #000000;
                    font-family: Arial, sans-serif;
                    text-align: center;
                    color: #ffffff;
                }
            </style>
            <body>
                <img src="/404.gif">
            </body>`;
    res.send(html);
});

app.listen(port, () => {
	console.log("Node application listening on port "+port);
});