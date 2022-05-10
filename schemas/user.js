const mongoose = require("mongoose")

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String },
  role: { type: String },
  secret: { type: String },
  tokens: [
    {
      accessToken: { type: String },
      refreshToken: { type: String },
      accessExpiry: { type: Number },
      refreshExpiry: { type: Number }
    }
  ]
})

const model = mongoose.model("UserSchema", UserSchema)

module.exports = model
