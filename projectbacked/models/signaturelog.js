const mongoose = require("mongoose");

const SignatureLogSchema = new mongoose.Schema({
  pdfId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'PDF'
  },

  pdf: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'PDF'
  },

  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },

  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },

  isSigned: {
    type: Boolean,
    default: false
  },

  isValid: {
    type: Boolean,
    default: false
  },

  allValid: {
    type: Boolean,
    default: false
  },

  signatureCount: {
    type: Number,
    default: 0
  },

  message: {
    type: String
  },

  error: {
    type: String
  },

  verifiedAt: {
    type: Date,
    default: Date.now
  },

  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("SignatureLog", SignatureLogSchema);