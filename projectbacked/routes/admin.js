const express = require('express');
const path = require('path');
const fs = require('fs');
const router = express.Router();
const { verifyToken, requireRole } = require('./tracepdf-auth-middleware');
const User = require('../models/User');
const PDF = require('../models/PDF');
const SignatureLog = require("../models/SignatureLog");

// GET /api/admin/dashboard - Admin dashboard statistics
router.get('/dashboard', verifyToken, async (req, res) => {
  try {
    // Check if user is admin
    const user = await User.findById(req.user.id);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    // Get statistics
    const totalPDFs = await PDF.countDocuments();
    const totalUsers = await User.countDocuments();
    const riskPDFs = await PDF.countDocuments({ riskLevel: 'High' });
    const signedPDFs = await PDF.countDocuments({ hasSignature: true });

    // Get recent uploads (last 10) with user info populated
    const recentUploads = await PDF.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .populate('userId', 'email firstName')
      .select('filename pages riskLevel hasSignature createdAt userId');

    // Get recent users (last 10)
    const recentUsers = await User.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .select('firstName secondName email role createdAt');

    // Get recent signature verifications (last 10) with PDF and user populated
    const recentVerifications = await SignatureLog.find()
      .sort({ verifiedAt: -1 })
      .limit(10)
      .populate('pdf', 'filename originalName')
      .populate('user', 'email firstName')
      .lean();

    res.json({
      stats: {
        totalPDFs,
        totalUsers,
        highRiskPDFs: riskPDFs,
        signedPDFs,
        percentageRisk: totalPDFs > 0 ? Math.round((riskPDFs / totalPDFs) * 100) : 0
      },
      recentUploads,
      recentUsers,
      recentVerifications
    });

  } catch (error) {
    console.error('Error fetching dashboard data:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// GET /api/admin/pdfs - List all PDFs with pagination
router.get('/pdfs', verifyToken, async (req, res) => {
  try {
    // Check if user is admin
    const user = await User.findById(req.user.id);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const pdfs = await PDF.find()
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .populate('userId', 'email firstName secondName')
      .select('filename pages riskLevel hasSignature hasJavaScript createdAt userId fileSize originalName');

    const total = await PDF.countDocuments();

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

// GET /api/admin/users - List all users with pagination
router.get('/users', verifyToken, async (req, res) => {
  try {
    // Check if user is admin
    const user = await User.findById(req.user.id);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const users = await User.find()
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .select('firstName secondName email role createdAt');

    const total = await User.countDocuments();

    // Count PDFs per user
    const usersWithCounts = await Promise.all(
      users.map(async (u) => {
        const pdfCount = await PDF.countDocuments({ userId: u._id });
        return {
          ...u.toObject(),
          pdfCount
        };
      })
    );

    res.json({
      users: usersWithCounts,
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
router.put('/users/:userId/role', verifyToken, async (req, res) => {
  try {
    // Check if requester is admin
    const requester = await User.findById(req.user.id);
    if (!requester || requester.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { userId } = req.params;
    const { role } = req.body;

    // Validate role
    if (!['user', 'admin', 'viewer'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    // Update user
    const updated = await User.findByIdAndUpdate(
      userId,
      { role, updatedAt: new Date() },
      { new: true }
    ).select('firstName secondName email role');

    if (!updated) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ success: true, message: 'User role updated', user: updated });

  } catch (error) {
    console.error('Error updating user role:', error);
    res.status(500).json({ error: 'Failed to update user role' });
  }
});

// DELETE /api/admin/pdfs/:pdfId - Delete a PDF and its file
router.delete('/pdfs/:pdfId', verifyToken, async (req, res) => {
  try {
    // Check if user is admin
    const user = await User.findById(req.user.id);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { pdfId } = req.params;

    // Find PDF
    const pdf = await PDF.findById(pdfId);
    if (!pdf) {
      return res.status(404).json({ error: 'PDF not found' });
    }

    // Delete file from disk
    const filePath = path.join(process.env.UPLOAD_DIR || './uploads', pdf.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    // Delete from database
    await PDF.findByIdAndDelete(pdfId);

    res.json({ success: true, message: 'PDF deleted' });

  } catch (error) {
    console.error('Error deleting PDF:', error);
    res.status(500).json({ error: 'Failed to delete PDF' });
  }
});

// GET /api/admin/stats - Quick stats endpoint
router.get('/stats', verifyToken, async (req, res) => {
  try {
    // Check if user is admin
    const user = await User.findById(req.user.id);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const stats = {
      totalPDFs: await PDF.countDocuments(),
      totalUsers: await User.countDocuments(),
      highRiskPDFs: await PDF.countDocuments({ riskLevel: 'High' }),
      mediumRiskPDFs: await PDF.countDocuments({ riskLevel: 'Medium' }),
      lowRiskPDFs: await PDF.countDocuments({ riskLevel: 'Low' }),
      signedPDFs: await PDF.countDocuments({ hasSignature: true }),
      admins: await User.countDocuments({ role: 'admin' })
    };

    res.json(stats);

  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// GET /api/admin/signature-logs - Get signature verification logs with proper population
router.get('/signature-logs', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const [logs, total] = await Promise.all([
      SignatureLog.find()
        .sort({ verifiedAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate('pdf', 'filename originalName')
        .populate('user', 'email firstName')
        .lean(),
      SignatureLog.countDocuments()
    ]);

    // Format for frontend - ensure arrays exist for safe access
    const formatted = logs.map(log => ({
      _id: log._id,
      verifiedAt: log.verifiedAt,
      pdfId: log.pdfId,
      userId: log.userId,
      isSigned: log.isSigned,
      isValid: log.isValid,
      allValid: log.allValid,
      signatureCount: log.signatureCount,
      message: log.message,
      // Ensure these are arrays or objects for frontend template
      pdf: log.pdf ? [log.pdf] : [],
      user: log.user ? [log.user] : []
    }));

    res.json({
      logs: formatted,
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

module.exports = router;