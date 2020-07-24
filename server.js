require('dotenv').config()

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')

const jwt = require('jsonwebtoken')

app.use(express.json())

const users = []

// Getting list of users
app.get('/users', authenticaticateToken, (req, res) => {
    res.json(users.filter(user => user.user === req.user.name))
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
    const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET)
    res.json({ accessToken: accessToken  })
})

// Get Token, verify and return the user to GET
function authenticaticateToken(req, res, next) {
     const authHeader = req.headers['authorization']
     //if there is authHeader then return the authHeader otherwise return undefined
     const token = authHeader && authHeader.split(' ')[1]
     //Checking
     if (token == null) return res.sendStatus(401)


     // verifying the token
     jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
         // token is invalid
         if (err) return res.sendStatus(403)
         // If valid token
         req.user = user
         next()
     })
  
}

app.listen(3000)