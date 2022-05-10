"use strict"

require("dotenv").config()

const express = require("express")

const app = express()
const PORT = 3000 || process.env.PORT

const mongoUrl = process.env.CONNECTION
const mongoose = require("mongoose")

const User = require("./schemas/user")

const cors = require("cors")
const cookieParser = require("cookie-parser")

const bcrypt = require("bcrypt")
const crypto = require("crypto")
const jwt = require("jsonwebtoken")

const rateLimit = require("express-rate-limit") // Do not use in-memory store in production
const toobusy = require("toobusy-js")
const hpp = require("hpp")

const contentType = require("content-type")
const getRawBody = require("raw-body")
const helmet = require("helmet")

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30, // Limit each IP to 30 requests per `window` (here, per 15 minutes)
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false // Disable the `X-RateLimit-*` headers
})

const privateKey = Buffer.from(process.env.PRIVATE_KEY, "base64").toString(
  "ascii"
)
const publicKey = Buffer.from(process.env.PUBLIC_KEY, "base64").toString(
  "ascii"
)

const allowedOrigins = ["https://127.0.0.1:3000", "http://localhost:3000"]

function credentials (req, res, next) {
  const origin = req.headers.origin
  if (allowedOrigins.includes(origin)) {
    res.header("Access-Control-Allow-Credentials", true)
  }
  next()
}

function errorHandler (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send(err.message)
}

function verifyRefreshToken (req, res, next) {
  const refreshToken = req.cookies.refreshToken
  if (!refreshToken) return res.sendStatus(401)
  console.log(refreshToken)
  jwt.verify(refreshToken, publicKey, (err, decoded) => {
    if (err) return res.sendStatus(403)
    req.decoded = decoded
    next()
  })
}

async function verifyAccessToken (req, res, next) {
  const accessToken = req.cookies.accessToken
  if (!accessToken) return res.sendStatus(401)
  console.log(accessToken)
  const oldUser = await User.find({
    "tokens.accessToken": accessToken
  }).exec()
  const user = oldUser[0]
  if (!user) return res.sendStatus(401)
  const foundToken = user.tokens.filter(
    (tokenArray) => accessToken === tokenArray.accessToken
  )
  if (!foundToken[0]) return res.sendStatus(401)
  if (
    foundToken[0].accessToken === accessToken &&
    Date.now() < foundToken[0].accessExpiry
  ) {
    req.user = user
    console.log(req.user)
    next()
  } else {
    res.sendStatus(401)
  }
}

const corsUsage = {
  origin: (origin, callback) => {
    if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
      callback(null, true)
    } else {
      callback(new Error("Not allowed by CORS"))
    }
  },
  optionsSuccessStatus: 200
}

const verifyRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req?.user) return res.sendStatus(403)
    const rolesArray = [...allowedRoles]
    const role = req.user.role
    if (!rolesArray.includes(role)) return res.sendStatus(401)
    next()
  }
}

try {
    mongoose.connect(encodeURI(mongoUrl), {
      useUnifiedTopology: true,
      useNewUrlParser: true
    })
  } catch (err) {
    console.error(err)
  }

// Tune to liking
app.use(credentials)

app.use(cors(corsUsage))

app.use(express.urlencoded({ extended: false, limit: "1kb" }))

app.use(express.json({ limit: "1kb" }))

app.use(cookieParser())

app.use(apiLimiter)

app.use(hpp())

/* Needs fixing, IMPORTANT FOR SECURITY
app.use(function (req, res, next) {
  if (!["POST", "DELETE", "GET"].includes(req.method)) {
    next()
    return
  }
  getRawBody(req, {
    length: req.headers["content-length"],
    limit: "1kb",
    encoding: contentType.parse(req).parameters.charset
  }, function (string) {
    req.text = string
    next()
  })
})
*/
// Tune headers to your liking
  app.use(helmet.hsts())
  app.use(helmet.frameguard({ action: "deny" }))
  app.use(helmet.noSniff())
  app.use(helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      frameAncestors: ["'none'"],
      imgSrc: ["'self'"],
      styleSrc: ["'none'"]
    }
  }))
  app.use(helmet.ieNoOpen())
  app.use(helmet.hidePoweredBy())

  app.use(function (req, res, next) {
    if (toobusy()) {
      res.send(503, "I\"m busy right now, sorry.")
    } else {
      next()
    }
  })

app.post("/api/register", async (req, res) => {
  const { user, pwd } = req.body
  if (!user || !pwd) {
    return res.status(400).json({
      message: "User and password are required. One or both are missing."
    })
  }

  try {
    const hashedPwd = await bcrypt.hash(pwd, 10)

    const oldUser = await User.findOne({
      username: user
    })

    if (oldUser) return res.sendStatus(409)
    const result = await User.create({
      username: user,
      role: "user",
      password: hashedPwd
    })

    console.log(result)

    res.status(201).json({ success: `New user, ${user} has been created!` })
  } catch (err) {
    res.status(500).json({ message: err.message })
  }
})

app.post("/api/authenticate", async (req, res) => {
  const cookies = req.cookies
  console.log(`Cookies at login: ${JSON.stringify(cookies)}`)
  const { user, pwd } = req.body
  if (!user || !pwd) {
    return res.status(400).json({
      message: "User and password are required. One or both are missing."
    })
  }
  const matchUser = await User.findOne({
    username: user
  })
  if (!matchUser) return res.sendStatus(401)
  const match = await bcrypt.compare(pwd, matchUser.password)
  if (match) {
    if (!matchUser.secret) {
      matchUser.secret = crypto.randomBytes(65).toString("base64")
    }
    const accessToken = crypto.randomBytes(100).toString("base64")
    const refreshToken = jwt.sign(
      {
        username: user,
        jwtid: crypto.randomBytes(100).toString("base64"),
        secret: matchUser.secret
      },
      privateKey,
      { algorithm: "PS256", expiresIn: "100d" }
    )
    let newRefreshTokenArray = []

    const currentDate = Date.now()
    let oldRefreshTokenArray = matchUser.tokens
    let data = ""
    if (oldRefreshTokenArray) {
      jwt.verify(refreshToken, publicKey, (err, decoded) => {
        if (err) return res.sendStatus(403)
        data = decoded
      })
      if (cookies?.refreshToken) {
        const oldRefreshToken = cookies.refreshToken
        if (!matchUser.tokens) return res.sendStatus(401)
        const foundToken = oldRefreshTokenArray.filter(
          (tokenArray) => oldRefreshToken === tokenArray.refreshToken
        )
        console.log(foundToken)
        if (
          foundToken &&
          foundToken[0] &&
          Date.now() < foundToken[0].refreshExpiry &&
          data
        ) {
          if (matchUser.secret === data.secret) {
            console.log("Refresh token reuse detected. (NOT THEFT DETECTION)")
            matchUser.tokens = []
            matchUser.secret = crypto.randomBytes(65).toString("base64")
          }
        } else if (user.secret === matchUser.secret) {
          matchUser.secret = crypto.randomBytes(65).toString("base64")
        }
        res.clearCookie("accessToken", {
          httpOnly: true,
          sameSite: "Strict",
          secure: true
        })
        res.clearCookie("refreshToken", {
          httpOnly: true,
          sameSite: "Strict",
          secure: true
        })
      }
    }
    oldRefreshTokenArray = matchUser.tokens
    newRefreshTokenArray = oldRefreshTokenArray.filter(
      (oldRT) => oldRT.refreshExpiry > currentDate
    )
    if (data && !data === "") {
      newRefreshTokenArray = newRefreshTokenArray.filter(
        (rt) => rt.refreshToken !== data.id
      )
    }
    const newTokens = {
      accessToken,
      refreshToken,
      accessExpiry: Date.now() + 3600000,
      refreshExpiry: Date.now() + 8640000000
    }
    matchUser.tokens = [...newRefreshTokenArray, newTokens]
    const result = await matchUser.save()
    console.log(result)

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      maxAge: 60 * 60 * 24 * 100 * 1000
    })

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      maxAge: 3600000
    })

    res.json({ success: `User ${user} is logged in!` })
  } else {
    res.sendStatus(401)
  }
})

app.post("/api/refresh", verifyRefreshToken, async (req, res) => {
  const decoded = req.decoded
  const refreshToken = req.cookies.refreshToken
  const oldUser = await User.find({
    "tokens.refreshToken": refreshToken
  }).exec()
  const user = oldUser[0]
  res.clearCookie("accessToken", {
    httpOnly: true,
    sameSite: "Strict",
    secure: true
  })
  res.clearCookie("refreshToken", {
    httpOnly: true,
    sameSite: "Strict",
    secure: true
  })
  if (!user) {
    const hackedUser = await User.findOne({ username: decoded.username })
    if (hackedUser.secret === decoded.secret) {
      console.log(
        `Refresh token theft detection has been detected for user ${decoded.username}`
      )
      hackedUser.tokens = []
      hackedUser.secret = crypto.randomBytes(65).toString("base64")
      const result = await hackedUser.save()
      console.log(result)
    } else {
      console.log(
        `Either a JWT was previously stolen from ${decoded.username} and token theft was detected, or the RSA private key has been discovered.`
      )
    }
    return res.sendStatus(403)
  }
  const newAccessToken = crypto.randomBytes(100).toString("base64")
  const newRefreshToken = jwt.sign(
    {
      username: user.username,
      jwtid: crypto.randomBytes(100).toString("base64"),
      secret: user.secret
    },
    privateKey,
    { algorithm: "PS256", expiresIn: "100d" }
  )
  const oldTokenArray = user.tokens
  let newRefreshTokenArray = oldTokenArray.filter(
    (rt) => rt.refreshToken !== refreshToken
  )
  newRefreshTokenArray = newRefreshTokenArray.filter(
    (rt) => rt.refreshExpiry < Date.now()
  )

  if (user.username !== decoded.username) return res.sendStatus(403)

  const newTokens = {
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
    accessExpiry: Date.now() + 3600000,
    refreshExpiry: Date.now() + 8640000000
  }

  user.tokens = [...newRefreshTokenArray, newTokens]
  await user.save()

  res.cookie("refreshToken", newRefreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    maxAge: 60 * 60 * 24 * 100 * 1000
  })

  res.cookie("accessToken", newAccessToken, {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    maxAge: 3600000
  })

  res.status(200).json({ success: "The tokens have been refreshed!" })
})

app.post(
  "/api/logout",
  verifyAccessToken,
  verifyRefreshToken,
  async (req, res) => {
    const refreshToken = req.cookies.refreshToken
    const oldUser = await User.find({ "tokens.refreshToken": refreshToken }).exec()
    const user = oldUser[0]
    if (!user) {
      res.clearCookie("accessToken", {
        httpOnly: true,
        sameSite: "Strict",
        secure: true
      })
      res.clearCookie("refreshToken", {
        httpOnly: true,
        sameSite: "Strict",
        secure: true
      })
      return res.sendStatus(204)
    }
    const oldTokenArray = user.tokens
    console.log(oldTokenArray)
    user.tokens = oldTokenArray.filter(rt => rt.refreshToken !== refreshToken)
    const result = await user.save()
    console.log(result)

    res.clearCookie("accessToken", {
      httpOnly: true,
      sameSite: "Strict",
      secure: true
    })
    res.clearCookie("refreshToken", {
      httpOnly: true,
      sameSite: "Strict",
      secure: true
    })
    res.sendStatus(204)
  }
)

app.post("/api/deleteAcount", verifyAccessToken, verifyRefreshToken, async (req, res) => {
  const { user, pwd } = req.body
  if (!user || !pwd) {
    return res.status(400).json({
      message: "User and password are required. One or both are missing."
    })
  }
  const userData = req.user
  if (!userData) return res.sendStatus(401)
  const match = await bcrypt.compare(pwd, userData.password)
  if (match) {
    await User.deleteOne({
      username: user
    })
  } else {
    res.sendStatus(401)
  }
})

app.post("/api/changePassword", verifyAccessToken, verifyRefreshToken, async (req, res) => {
  const { user, pwd } = req.body
  if (!user || !pwd) {
    return res.status(400).json({
      message: "User and password are required. One or both are missing."
    })
  }
  const matchUser = req.user
  try {
    const match = await bcrypt.compare(pwd, matchUser.password)
    if (!match) return res.sendStatus(401)
    const hashedPwd = await bcrypt.hash(pwd, 10)

    const result = await User.updateOne({
      username: user
    }, {
      password: hashedPwd
    })

    console.log(result)

    res.status(200).json({ success: "User's password has been changed." })
  } catch (err) {
    res.status(500).json({ message: err.message })
  }
})

app.post("/api/dog", verifyAccessToken, verifyRoles("user", "admin", ""), (req, res) => {
  res.send(req.user)
})

app.use(errorHandler)

// Do not use in production
process.on("uncaughtException", function (err) {
  console.log("Caught exception: " + err)
  // Use "throw err" in production
})

process.on("unhandledRejection", function (err) {
  console.log("Caught unhandled rejection: " + err)
  // Use "throw err" in production
})

mongoose.connection.once("open", () => {
  console.log("Connected to MongoDB")
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`))
})
