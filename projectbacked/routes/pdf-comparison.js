// Add this to your /routes/admin.js or create /routes/pdf-comparison.js

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { verifyToken } = require('./tracepdf-auth-middleware');
const PDF = require('../models/PDF');
const User = require('../models/User');

// Helper: Calculate SHA-256 hash of file
function calculateFileHash(filePath) {
  try {
    const fileBuffer = fs.readFileSync(filePath);
    const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
    return hash;
  } catch (error) {
    console.error('Error calculating hash:', error);
    return null;
  }
}

// GET /api/pdf/compare/:pdfId - Compare PDF versions
router.get('/compare/:pdfId', verifyToken, async (req, res) => {
  try {
    const { pdfId } = req.params;

    // Fetch PDF with version history
    const pdf = await PDF.findById(pdfId).populate('userId', 'email firstName');

    if (!pdf) {
      return res.status(404).json({ error: 'PDF not found' });
    }

    // Check if user owns PDF or is admin
    const user = await User.findById(req.user.id);
    if (pdf.userId._id.toString() !== req.user.id && user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Get version details
    const versions = pdf.versions || [];
    
    const versionDetails = versions.map(v => ({
      versionType: v.versionType,
      filename: v.filename,
      hash: v.hash,
      fileSize: v.fileSize,
      timestamp: v.timestamp,
      description: v.description,
      url: `/api/pdf/download/${pdfId}?version=${v.versionType}`
    }));

    // Detect modifications
    let modificationDetected = false;
    let modifications = [];

    if (versions.length >= 2) {
      const original = versions.find(v => v.versionType === 'original');
      const current = versions[versions.length - 1];

      if (original && current && original.hash !== current.hash) {
        modificationDetected = true;
        modifications.push({
          type: 'Hash Mismatch',
          description: 'File content has changed from original',
          severity: 'High',
          originalHash: original.hash,
          currentHash: current.hash
        });
      }

      if (original && current && original.fileSize !== current.fileSize) {
        modifications.push({
          type: 'Size Change',
          description: `File size changed: ${original.fileSize} → ${current.fileSize} bytes`,
          severity: 'Medium',
          originalSize: original.fileSize,
          currentSize: current.fileSize
        });
      }
    }

    res.json({
      success: true,
      pdf: {
        id: pdf._id,
        originalName: pdf.originalName,
        filename: pdf.filename,
        uploadedBy: pdf.userId.email,
        createdAt: pdf.createdAt,
        signedAt: pdf.signedAt,
        riskLevel: pdf.riskLevel,
        hasSignature: pdf.hasSignature,
        isTampered: pdf.isTampered
      },
      versions: versionDetails,
      modificationDetected,
      modifications,
      analysis: {
        totalVersions: versions.length,
        originalHash: pdf.originalHash,
        currentHash: pdf.hash,
        signatureCount: pdf.signatureCount,
        hasIncrementalUpdates: pdf.hasIncrementalUpdates
      }
    });

  } catch (error) {
    console.error('Error comparing PDFs:', error);
    res.status(500).json({ error: 'Failed to compare PDFs' });
  }
});

// GET /api/pdf/verify/:pdfId - Detailed verification report
router.get('/verify/:pdfId', verifyToken, async (req, res) => {
  try {
    const { pdfId } = req.params;

    const pdf = await PDF.findById(pdfId).populate('userId', 'email firstName');

    if (!pdf) {
      return res.status(404).json({ error: 'PDF not found' });
    }

    // Check permissions
    const user = await User.findById(req.user.id);
    if (pdf.userId._id.toString() !== req.user.id && user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Build verification report
    const report = {
      success: true,
      pdf: {
        id: pdf._id,
        name: pdf.originalName || pdf.filename,
        uploadedBy: pdf.userId.email,
        uploadedAt: pdf.createdAt,
        pages: pdf.pages,
        fileSize: pdf.fileSize
      },

      // Signature Analysis
      signature: {
        present: pdf.hasSignature,
        count: pdf.signatureCount || 0,
        tampered: pdf.tamperDetails?.signatureTampered || false,
        validSignatures: 0  // Would need @ninja-labs/verify-pdf to check
      },

      // Integrity Analysis
      integrity: {
        isTampered: pdf.isTampered,
        originalHash: pdf.originalHash,
        currentHash: pdf.hash,
        hashMatch: pdf.originalHash === pdf.hash,
        details: pdf.tamperDetails || {}
      },

      // Security Analysis
      security: {
        riskLevel: pdf.riskLevel,
        riskScore: pdf.riskScore || 0,
        hasJavaScript: pdf.hasJavaScript,
        hasEmbeddedFiles: pdf.hasEmbeddedFiles,
        hasIncrementalUpdates: pdf.hasIncrementalUpdates,
        incrementalUpdateCount: pdf.tamperDetails?.eofCount || 0,
        deletionDetected: pdf.tamperDetails?.deletionDetected || false,
        freedObjects: pdf.tamperDetails?.freedObjects || 0
      },

      // Metadata
      metadata: pdf.metadata || {},

      // Flags/Warnings
      flags: pdf.flags || [],

      // Version History
      versionHistory: (pdf.versions || []).map(v => ({
        type: v.versionType,
        timestamp: v.timestamp,
        description: v.description
      }))
    };

    res.json(report);

  } catch (error) {
    console.error('Error verifying PDF:', error);
    res.status(500).json({ error: 'Failed to verify PDF' });
  }
});

// POST /api/pdf/store-version/:pdfId - Store a new version of PDF
router.post('/store-version/:pdfId', verifyToken, async (req, res) => {
  try {
    const { pdfId } = req.params;
    const { versionType, filename, description } = req.body;

    const pdf = await PDF.findById(pdfId);
    if (!pdf) {
      return res.status(404).json({ error: 'PDF not found' });
    }

    // Verify ownership
    if (pdf.userId.toString() !== req.user.id) {
      const user = await User.findById(req.user.id);
      if (user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
      }
    }

    // Calculate hash of new file
    const uploadDir = process.env.UPLOAD_DIR || './uploads';
    const filePath = require('path').join(uploadDir, filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    const fileBuffer = fs.readFileSync(filePath);
    const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
    const fileSize = fileBuffer.length;

    // Add version to array
    pdf.versions = pdf.versions || [];
    pdf.versions.push({
      versionType,
      filename,
      hash,
      fileSize,
      timestamp: new Date(),
      description: description || `${versionType} version`
    });

    // Update main hash if this is the current version
    if (versionType !== 'original') {
      pdf.hash = hash;
      pdf.updatedAt = new Date();
    }

    // Set original hash if first upload
    if (!pdf.originalHash) {
      pdf.originalHash = hash;
    }

    await pdf.save();

    res.json({
      success: true,
      message: `${versionType} version stored`,
      version: {
        type: versionType,
        hash,
        fileSize,
        timestamp: new Date()
      }
    });

  } catch (error) {
    console.error('Error storing version:', error);
    res.status(500).json({ error: 'Failed to store version' });
  }
});

// POST /api/pdf/flag/:pdfId - Flag a PDF for admin review
router.post('/flag/:pdfId', verifyToken, async (req, res) => {
  try {
    const pdf = await PDF.findById(req.params.pdfId);
    if (!pdf) return res.status(404).json({ error: 'PDF not found' });

    // Only owner or admin can flag
    const user = await User.findById(req.user.id);
    if (pdf.userId.toString() !== req.user.id && user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    pdf.flags = [...(pdf.flags || []), `Flagged by user: ${req.body.reason}`];
    pdf.flaggedForReview = true;
    await pdf.save();

    res.json({ success: true, message: 'PDF flagged for review' });
  } catch (error) {
    console.error('Error flagging PDF:', error);
    res.status(500).json({ error: 'Failed to flag PDF' });
  }
});
// GET /api/pdf/download/:pdfId - Download original or current PDF
router.get('/download/:pdfId', verifyToken, async (req, res) => {
  try {
    const pdf = await PDF.findById(req.params.pdfId);
    if (!pdf) return res.status(404).json({ error: 'PDF not found' });

    // Check ownership
    const user = await User.findById(req.user.id);
    if (pdf.userId.toString() !== req.user.id && user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const version = req.query.version || 'original';

    // Find the right filename from versions array
    const versionRecord = pdf.versions?.find(v => v.versionType === version);
    const filename = versionRecord?.filename || pdf.filename;

    const uploadDir = process.env.UPLOAD_DIR || path.join(__dirname, '../uploads');
    const filePath  = path.join(uploadDir, filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found on disk' });
    }

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${pdf.originalName}"`);
    fs.createReadStream(filePath).pipe(res);

  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ error: 'Failed to download PDF' });
  }
});
module.exports = router;