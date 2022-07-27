const jwt = require('jose');
require('dotenv').config();

const user = {
    id:42,
    nom: "Eau Tarie",
    email:'Eautarie@gmail.com',
    admin:true,
};

function generateAccessToken(user) {
     return new jwt.SignJWT(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn:'86400s'});
};

const accessToken = generateAccessToken(user);
console.log('access token', accessToken);