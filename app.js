const express = require('express');
const app = express();
const session = require('express-session');
const bodyParser = require('body-parser');
const { authenticator } = require('otplib')
const QRCode = require('qrcode')
const jwtoken = require('jsonwebtoken')
var { expressjwt: jwt } = require("express-jwt");
const db = require('./models');
const User = db.User;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.set('view engine', 'ejs');
app.use(express.static(__dirname + '/views'));
app.use(session({
    secret: 'supersecret',
    resave: true,
    saveUninitialized: true
}))


//Signup for the Authentication
app.get('/', (req, res) => {
    res.render('signup.ejs')
})

//Store the email and secret in database
app.post('/sign-up', async (req, res) => {
    const email = req.body.email,
    secret = authenticator.generateSecret();
    try {

        const check_email = await User.findOne({ where: { email: req.body.email } });
        if (check_email) 
        {
            return res.status(200).json({ msg: 'email is already exists' });
        }
        const user = await User.create(
        {
            email: email,
            secret: secret
        })

        //generate qr and put it in session
        QRCode.toDataURL(authenticator.keyuri(email, '2FA Node App', secret), (err, url) => {
            if (err) {
                throw err
            }
            req.session.qr = url
            req.session.email = email
            res.redirect('/signup-2fa')
        })
    }
    catch (error) {
        res.status(400).json({
            message: error.message
        })
    }
});

//Check the two step authentication
app.get('/signup-2fa', (req, res) => {
    if (!req.session.qr) 
    {
        return res.redirect('/')
    }
    return res.render('signup-2fa.ejs', { qr: req.session.qr })
})

//Verify
app.post('/signup-2fa', (req, res) => {
    if (!req.session.email) 
    {
        return res.redirect('/')
    }
    const email = req.session.email,
    code = req.body.code
    return verifyLogin(email, code, req, res, '/signup-2fa')
})


//verify the email and code with database
async function verifyLogin(email, code, req, res, failUrl) {
    try {
        const user = await User.findOne({
            where: {
                email: email
            }
        });
        if (!user) {
            return res.redirect('/');
        }
        if (!authenticator.check(code, user.secret)) 
        {
            return res.redirect(failUrl);
        }

        // Correct, add JWT to session
        req.session.qr = null;
        req.session.email = null;
        req.session.token = jwtoken.sign(email, 'supersecret');
        var email = encodeURIComponent(email);
        // Redirect to "private" page
        return res.redirect('/private?email=' + email);
    } catch (err) {
        throw err;
    }
}



app.get('/login', (req, res) => {
    return res.render('login.ejs')
})

app.post('/login', (req, res) => {
    //verify login
    const email = req.body.email,
        code = req.body.code

    return verifyLogin(email, code, req, res, '/login')
})


const jwtMiddleware = jwt({
    secret: 'supersecret',
    algorithms: ["HS256"],
    getToken: (req) => {
        return req.session.token
    }
});

app.get('/private', jwtMiddleware, (req, res) => {
    return res.render('private.ejs', { email: req.query.email })
})

app.get('/logout', jwtMiddleware, (req, res) => {
    req.session.destroy()
    return res.redirect('/')
})
app.listen(3000, (req, res) => {
    console.log("App is Running Successfully");
})