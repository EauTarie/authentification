const jwt = require('jsonwebtoken');
require('dotenv').config();
            const bcrypt= require('bcrypt');

const express = require('express');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// A voir pour plus tard
(async () => {

    const bcrypt = require('bcrypt')

    try {

        let text = "okay"

        // let salt = await bcrypt.genSalt(10)
        let hash = await bcrypt.hash(text, await bcrypt.genSalt(10))
        let hash2 = await bcrypt.hash(text, await bcrypt.genSalt(10))
        console.log(hash)
        console.log(hash2)
        let compare = await bcrypt.compare(text, hash)
        let compare2 = await bcrypt.compare(text, hash2)
        console.log(compare)
        console.log(compare2)

    } catch (error) {
        console.log(error.message)
    }

})()

//Fin 

function User(userId,first,mail,pass,admin) {

    this.id= userId;
    this.nom= first;
    this.email= mail;
    this.password= pass;
    this.admin= admin;

};

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '86400s' });
};

function generateRefreshToken(user) {
    return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '86400s' });
};

app.post('/api/register',async (req, res) => {
    if (req.body.email == User.email) {
        res.status(401).send('Compte déjà existant')
    } else {
                let hash3
                await bcrypt.genSalt(10, async(err, salt) => {
                    hash3 = await bcrypt.hash(req.body.pass,salt);
                    console.log(hash3);
                })
            res.status(201).send('Compte créer avec succès');
            user = new User({
                userId: req.body.id,
                first:req.body.nom,
                mail: req.body.email,
                pass: hash3,
                admin:req.body.admin
            });
            console.log(user)
        }
    });

app.post('/api/login', (req, res) => {
    if (req.body.email !== user.email) {
        res.status(401).send('Compte inconnu');
        return;
    }
    if (req.body.password !== 'coucou') {
        res.status(401).send('Compte inconnu');
        return;
    }
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    res.send({
        accessToken,
        refreshToken
    });
});


app.post('/api/refreshToken', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.sendStatus(401)
    }

    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(401);
        }
        delete user.iat;
        delete user.exp;
        const refreshedToken = generateAccessToken(user);
        res.send({
            accessToken: refreshedToken,
        })
    });
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.sendStatus(401)
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(401);
        }
        req.user = user;
        next();
    });
}

app.get('/api/me', authenticateToken, (req, res) => {
    res.send(req.user);
});
app.listen(3000, () => { console.log('Server running on port 3000') });