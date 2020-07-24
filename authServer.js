require('dotenv').config()

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')

const jwt = require('jsonwebtoken')

app.use(express.json())

const users = []

//Temporialy, to be stored on db
let refreshTokens = []

app.post('token', (req, res) => {
    const refreshToken = req.body.token
    if (refreshToken == null) return res.sendStatus(401)
    if(!refreshToken.includes(refreshToken))return res.sendStatus(403)
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if(err) return res.sendStatus(403)
        const accessToken = generateAccessToken({ name: user.name })
        res.json({ accessToken: accessToken })
    })
})

app.delete('/logout',(req, res) => {
  refreshTokens = refreshTokens.filter(token => token !== req.body.token)
  res.sendStatus(204)
})

// Creating user and sending status, also hashing the created user password
app.post('/users', async (req, res) => {
   try {
       const hashedPassword = await bcrypt.hash(req.body.password, 10)
       const user = { name: req.body.name, password: hashedPassword }
       users.push(user)
       res.status(201).send()
   } catch {
       res.status(500).send()
   }
})

// Login users
app.post('/users/login', async (req, res) => {
    const user = users.find(user => user.name === req.body.name)
    if (user == null) {
       return res.status(400).send('Cannot find user')
    } 
    try {
       if(await bcrypt.compare(req.body.password, user.password)) {
           res.send('Success')
       } else {
           res.send('Not Allowed')
       }
    } catch {
        res.status(500).send()
    }
   
 // const username = req.body.username
    // const user = { name: username }

    const accessToken = generateAccessToken(user)
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
    // push the new refreshtokens
    refreshTokens.push(refreshToken)
    res.json({ accessToken: accessToken, refreshToken: refreshToken  })

})

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET), {expireIn: '15m'   }
}

app.listen(4000)