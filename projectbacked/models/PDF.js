const mongoose = require("mongoose");

const PDFSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  // Original file info
  filename: {
    type: String,
    required: true
  },

  originalName: {
    type: String
  },

  filePath: {
    type: String
  },

  fileSize: {
    type: Number,
    default: 0
  },

  // Hash tracking (for modification detection)
  hash: {
    type: String,
    index: true  // Index for fast lookup
  },

  originalHash: {
    type: String,  // Store hash of original file
    description: 'Hash of PDF before any modifications'
  },

  // Version tracking
  versions: [{
    versionType: {
      type: String,
      enum: ['original', 'signed', 'modified'],
      default: 'original'
    },
    filename: String,
    hash: String,
    fileSize: Number,
    timestamp: { type: Date, default: Date.now },
    description: String
  }],

  // PDF analysis fields
  pages: {
    type: Number,
    default: 0
  },

  hasSignature: {
    type: Boolean,
    default: false
  },

  signatureCount: {
    type: Number,
    default: 0
  },

  hasIncrementalUpdates: {
    type: Boolean,
    default: false
  },

  hasLayers: {
    type: Boolean,
    default: false
  },

  hasJavaScript: {
    type: Boolean,
    default: false
  },

  hasEmbeddedFiles: {
    type: Boolean,
    default: false
  },

  riskLevel: {
    type: String,
    enum: ['Low', 'Medium', 'High'],
    default: "Low"
  },

  riskScore: {
    type: Number,
    default: 0
  },

  // Tampering detection
  isTampered: {
    type: Boolean,
    default: false
  },

  tamperDetails: {
    signatureTampered: Boolean,
    deletionDetected: Boolean,
    freedObjects: Number,
    hasIncrementalUpdates: Boolean,
    eofCount: Number
  },

  // Metadata
  metadata: {
    author: String,
    title: String,
    creator: String,
    created: String,
    subject: String
  },

  flags: [String],

  // Timestamps
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  },

  updatedAt: {
    type: Date,
    default: Date.now
  },

  signedAt: Date,
  
  lastModifiedAt: Date
});

// Create index for user queries
PDFSchema.index({ userId: 1, createdAt: -1 });

module.exports = mongoose.model("PDF", PDFSchema);