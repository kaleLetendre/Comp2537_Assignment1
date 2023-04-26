require('dotenv').config();

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;

const MongoClient = require("mongodb").MongoClient;
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/?retryWrites=true`;
var database = new MongoClient(atlasURI, {useNewUrlParser: true, useUnifiedTopology: true});
// output a message if we are connected to the database
database.connect((err, db) => {
    if (err) {
        console.log("Error connecting to database");
        throw err;
    }
    console.log("Connected to database");
});

module.exports = {database};