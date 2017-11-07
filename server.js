// =======================
// get the packages we need ============
// =======================
var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var morgan = require('morgan');
var ldap = require('ldapjs');

var jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens
var config = require('./config'); // get our config file

// =======================
// configuration =========
// =======================
var port = process.env.PORT || 8080; // used to create, sign, and verify tokens
app.set('superSecret', config.secret); // secret variable

// use body parser so we can get info from POST and/or URL parameters
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// use morgan to log requests to the console
app.use(morgan('dev'));

var client = ldap.createClient({
    url: `${config.ldapProtocol}://${config.ldapHost}:${config.ldapPort}`
});

// API ROUTES -------------------

// get an instance of the router for api routes
var apiRoutes = express.Router();

// route to authenticate a user (POST http://localhost:8080/api/authenticate)
apiRoutes.post('/authenticate', function (req, res) {

    client.bind(`cn=${req.body.username},ou=staff,dc=pmdigital,dc=com`, `${req.body.password}`, function (err) {

        if (err) throw err;

        // if user is found and password is right
        // create a token with only our given payload
        // we don't want to pass in the entire user since that has the password
        const payload = {
            username: `${req.body.username}`
        };
        var token = jwt.sign(payload, app.get('superSecret'), {
            expiresIn: 900 // expires in 15 minutes
        });

        // return the information including token as JSON
        res.json({
            success: true,
            message: 'Enjoy your token!',
            token: token
        });
    });
});

// route middleware to verify a token
apiRoutes.use(function (req, res, next) {

    // check header or url parameters or post parameters for token
    var token = req.body.token || req.query.token || req.headers['x-access-token'];

    // decode token
    if (token) {

        // verifies secret and checks exp
        jwt.verify(token, app.get('superSecret'), function (err, decoded) {
            if (err) {
                return res.json({ success: false, message: 'Failed to authenticate token.' });
            } else {
                // if everything is good, save to request for use in other routes
                req.decoded = decoded;
                next();
            }
        });

    } else {

        // if there is no token
        // return an error
        return res.status(403).send({
            success: false,
            message: 'No token provided.'
        });

    }
});


// route to show a random message (GET http://localhost:8080/api/)
apiRoutes.get('/', function (req, res) {
    res.json({ message: 'Welcome to the coolest API on earth!' });
});

// route to return all users (GET http://localhost:8080/api/verify)
apiRoutes.get('/verify', function (req, res) {

    client.search(`cn=${req.decoded.username},ou=staff,dc=pmdigital,dc=com`, function (err, ldapResponse) {
        if (err) throw err;
        
        var user = {};

        ldapResponse.on('searchEntry', function (entry) {
            console.log('entry: ' + JSON.stringify(entry.object));
            user = entry.object;
        });
        ldapResponse.on('searchReference', function (referral) {
            console.log('referral: ' + referral.uris.join());
        });
        ldapResponse.on('error', function (err) {
            console.error('error: ' + err.message);
        });
        ldapResponse.on('end', function (result) {
            console.log('status: ' + result.status);
            return res.status(200).send({
                success: true,
                user: user
            });
        });
    });

});

app.use('/api', apiRoutes);

// =======================
// start the server ======
// =======================
app.listen(port);
console.log('Magic happens at http://localhost:' + port);

