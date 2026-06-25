// Routes for signature verification and admin dashboard
const express = require('express');
const path = require('path');
const fs = require('fs');
const router = express.Router();
const { verifyToken, requireRole } = require('./tracepdf-auth-middleware');
const { verifyAndLogSignature } = require('./tracepdf-signature-service');

// POST /api/verify-signature - Verify a PDF's digital signature
router.post('/verify-signature/:pdfId', verifyToken, async (req, res) => {
  try {
    const { pdfId } = req.params;
    const userId = req.user.id;

    // Get PDF from database
    const pdf = await req.db.collection('pdfs').findOne({ _id: pdfId });

    if (!pdf) {
      return res.status(404).json({ error: 'PDF not found' });
    }

    // Check user has access to this PDF
    if (pdf.userId !== userId && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Get file path
    const filePath = path.join(process.env.UPLOAD_DIR || './uploads', pdf.filename);

    // Verify signature
    const result = await verifyAndLogSignature(
      filePath,
      pdfId,
      userId,
      req.db.collection('pdfs'),
      req.db.collection('signatureLogs')
    );

    res.json(result);

  } catch (error) {
    console.error('Error verifying signature:', error);
    res.status(500).json({ error: 'Failed to verify signature', details: error.message });
  }
});

// GET /api/admin/dashboard - Admin dashboard data
router.get('/admin/dashboard', verifyToken, requireRole(['admin']), async (req, res) => {
  try {
    const db = req.db;

    // Get statistics
    const totalPDFs = await db.collection('pdfs').countDocuments();
    const totalUsers = await db.collection('users').countDocuments();
    const signedPDFs = await db.collection('pdfs').countDocuments({
      'lastSignatureVerification.isSigned': true
    });
    const invalidPDFs = await db.collection('pdfs').countDocuments({
      'lastSignatureVerification.isValid': false
    });

    // Get recent activities
    const recentVerifications = await db.collection('signatureLogs')
      .find()
      .sort({ verifiedAt: -1 })
      .limit(10)
      .toArray();

    const recentUploads = await db.collection('pdfs')
      .find()
      .sort({ uploadedAt: -1 })
      .limit(10)
      .toArray();

    res.json({
      stats: {
        totalPDFs,
        totalUsers,
        signedPDFs,
        invalidPDFs,
        percentageSigned: totalPDFs > 0 ? Math.round((signedPDFs / totalPDFs) * 100) : 0
      },
      recentVerifications,
      recentUploads
    });

  } catch (error) {
    console.error('Error fetching dashboard data:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// GET /api/admin/pdfs - List all PDFs with signature status
router.get('/admin/pdfs', verifyToken, requireRole(['admin']), async (req, res) => {
  try {
    const db = req.db;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const pdfs = await db.collection('pdfs')
      .aggregate([
        {
          $lookup: {
            from: 'users',
            localField: 'userId',
            foreignField: '_id',
            as: 'owner'
          }
        },
        { $sort: { uploadedAt: -1 } },
        { $skip: skip },
        { $limit: limit },
        {
          $project: {
            filename: 1,
            originalName: 1,
            uploadedAt: 1,
            size: 1,
            'owner.email': 1,
            'lastSignatureVerification.isSigned': 1,
            'lastSignatureVerification.isValid': 1,
            'lastSignatureVerification.signatureCount': 1,
            'lastSignatureVerification.verifiedAt': 1,
            integrityHash: 1
          }
        }
      ])
      .toArray();

    const total = await db.collection('pdfs').countDocuments();

    res.json({
      pdfs,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });

  } catch (error) {
    console.error('Error fetching PDFs:', error);
    res.status(500).json({ error: 'Failed to fetch PDFs' });
  }
});

// GET /api/admin/users - List all users
router.get('/admin/users', verifyToken, requireRole(['admin']), async (req, res) => {
  try {
    const db = req.db;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const users = await db.collection('users')
      .aggregate([
        { $sort: { createdAt: -1 } },
        { $skip: skip },
        { $limit: limit },
        {
          $lookup: {
            from: 'pdfs',
            localField: '_id',
            foreignField: 'userId',
            as: 'pdfs'
          }
        },
        {
          $project: {
            email: 1,
            role: 1,
            createdAt: 1,
            lastLogin: 1,
            pdfCount: { $size: '$pdfs' }
          }
        }
      ])
      .toArray();

    const total = await db.collection('users').countDocuments();

    res.json({
      users,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });

  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// PUT /api/admin/users/:userId/role - Update user role
router.put('/admin/users/:userId/role', verifyToken, requireRole(['admin']), async (req, res) => {
  try {
    const { userId } = req.params;
    const { role } = req.body;

    if (!['user', 'admin', 'viewer'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    const db = req.db;
    const result = await db.collection('users').updateOne(
      { _id: userId },
      { $set: { role, updatedAt: new Date() } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ success: true, message: 'User role updated' });

  } catch (error) {
    console.error('Error updating user role:', error);
    res.status(500).json({ error: 'Failed to update user role' });
  }
});

// GET /api/admin/signature-logs - View signature verification audit log
router.get('/admin/signature-logs', verifyToken, requireRole(['admin']), async (req, res) => {
  try {
    const db = req.db;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const logs = await db.collection('signatureLogs')
      .aggregate([
        {
          $lookup: {
            from: 'pdfs',
            localField: 'pdfId',
            foreignField: '_id',
            as: 'pdf'
          }
        },
        {
          $lookup: {
            from: 'users',
            localField: 'userId',
            foreignField: '_id',
            as: 'user'
          }
        },
        { $sort: { verifiedAt: -1 } },
        { $skip: skip },
        { $limit: limit },
        {
          $project: {
            verifiedAt: 1,
            isSigned: 1,
            allValid: 1,
            signatureCount: 1,
            message: 1,
            error: 1,
            'pdf.originalName': 1,
            'user.email': 1
          }
        }
      ])
      .toArray();

    const total = await db.collection('signatureLogs').countDocuments();

    res.json({
      logs,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });

  } catch (error) {
    console.error('Error fetching signature logs:', error);
    res.status(500).json({ error: 'Failed to fetch signature logs' });
  }
});

// DELETE /api/admin/pdfs/:pdfId - Delete a PDF (admin only)
router.delete('/admin/pdfs/:pdfId', verifyToken, requireRole(['admin']), async (req, res) => {
  try {
    const { pdfId } = req.params;
    const db = req.db;

    const pdf = await db.collection('pdfs').findOne({ _id: pdfId });

    if (!pdf) {
      return res.status(404).json({ error: 'PDF not found' });
    }

    // Delete file from disk
    const filePath = path.join(process.env.UPLOAD_DIR || './uploads', pdf.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    // Delete from database
    await db.collection('pdfs').deleteOne({ _id: pdfId });
    await db.collection('signatureLogs').deleteMany({ pdfId });

    res.json({ success: true, message: 'PDF deleted' });

  } catch (error) {
    console.error('Error deleting PDF:', error);
    res.status(500).json({ error: 'Failed to delete PDF' });
  }
});

module.exports = router;