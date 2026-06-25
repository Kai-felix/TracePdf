const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({

  firstName: {
    type: String,
    required: true
  },

  secondName: {
    type: String,
    required: true
  },

  email: {
    type: String,
    required: true,
    unique: true
  },


  password: {
    type: String,
    required: true
  },

  role: {
    type: String,
    default: "user"
  }

});

module.exports = mongoose.model("User", UserSchema);