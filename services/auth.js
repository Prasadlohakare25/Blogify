const JWT = require("jsonwebtoken");

const secret = "$peedItIs";

function createTokenForUser(user) {
    const payload = {
        _id: user._id,
        email: user.email,
        profilePhoto: user.profilePhoto,
        role: user.role,
    };

    const token = JWT.sign(payload, secret);
    return token;
}

function validateToken(token) {
    const payload = JWT.verify(token, secret);
    // console.log(secret);
    return payload;
}

module.exports = {
    createTokenForUser, validateToken
}