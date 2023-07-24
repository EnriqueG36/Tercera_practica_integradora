//Jason Web Token
const jwt = require ('jsonwebtoken')

const PRIVATE_KEY = "coderSecret"

const generateToken = (user) => {
    const token = jwt.sign({user}, PRIVATE_KEY, {expiresIn: '2m'}) //'24h'
    return token
}

const authToken = (req, res, next) => {
    const authHeader = req.headers.authorization
    if(!authHeader) return res.status(401).send({status: error, message: "No se encontró el jason web token"})
    const token = authHeader.split(' ')[1]
    jwt.verify(token, PRIVATE_KEY, (error, credentials)=>{
        if(error) return res.status(403).send({error: "Not authorized"})
        req.user = credentials.user
        next()
    })

}

module.exports = { generateToken, authToken }