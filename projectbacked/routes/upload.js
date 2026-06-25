const express = require("express");
const router = express.Router();
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { verifyToken } = require('./tracepdf-auth-middleware');
const PDF = require("../models/PDF");
const User = require("../models/User");
const { verifyPDFSignatures } = require('./tracepdf-signature-service');

// Setup multer
const uploadDir = process.env.UPLOAD_DIR || path.join(__dirname, "../uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    file.mimetype === "application/pdf" ? cb(null, true) : cb(new Error("Only PDFs allowed"));
  },
  limits: { fileSize: 50 * 1024 * 1024 }
});

// POST upload
router.post("/", verifyToken, upload.single("pdf"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const user = await User.findById(req.user.id);
    if (!user) {
      fs.unlinkSync(req.file.path);
      return res.status(404).json({ error: "User not found" });
    }

    const verificationResult = await verifyPDFSignatures(req.file.path);
    if (!verificationResult.success) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: verificationResult.error });
    }

    const pdfRecord = new PDF({
      userId: req.user.id,
      filename: req.file.filename,
      originalName: req.file.originalname,
      filePath: req.file.path,
      fileSize: req.file.size,
      hash: verificationResult.hash,
      originalHash: verificationResult.hash,
      pages: verificationResult.pages,
      riskLevel: verificationResult.riskLevel,
      riskScore: verificationResult.riskScore,
      hasSignature: verificationResult.isSigned,
      signatureCount: verificationResult.signatureCount,
      hasJavaScript: verificationResult.hasJavaScript,
      hasEmbeddedFiles: verificationResult.hasEmbeddedFiles,
      isTampered: verificationResult.tamperDetails.signatureTampered,
      tamperDetails: verificationResult.tamperDetails,
      flags: verificationResult.flags,
      metadata: verificationResult.metadata,
      versions: [{
        versionType: 'original',
        filename: req.file.filename,
        hash: verificationResult.hash,
        fileSize: req.file.size,
        timestamp: new Date(),
        description: 'Original upload'
      }]
    });

    await pdfRecord.save();

    res.status(201).json({
      success: true,
      message: "PDF uploaded and verified",
      pdf: { id: pdfRecord._id, originalName: pdfRecord.originalName },
      verification: {
        hash: verificationResult.hash,
        pages: verificationResult.pages,
        isSigned: verificationResult.isSigned,
        riskLevel: verificationResult.riskLevel,
        flags: verificationResult.flags
      }
    });

  } catch (error) {
    console.error("Upload error:", error);
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.status(500).json({ error: error.message });
  }
});
// GET all uploaded PDFs for the logged-in user
router.get("/", verifyToken, async (req, res) => {
  try {
    const pdfs = await PDF.find({ userId: req.user.id })
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      pdfs
    });

  } catch (error) {
    console.error("Error loading PDFs:", error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});


module.exports = router;