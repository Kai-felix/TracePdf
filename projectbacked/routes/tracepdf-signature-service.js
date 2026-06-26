const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const verifyPDFSignatures = async (filePath) => {
  try {
    if (!fs.existsSync(filePath)) {
      return {
        success: false,
        error: 'PDF file not found',
        isSigned: false,
        signatures: []
      };
    }

    const fileBuffer = fs.readFileSync(filePath);
    const fileContent = fileBuffer.toString('latin1');

    // Calculate SHA-256 hash
    const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    let verificationResult = {
      isSigned: false,
      signatures: [],
      allValid: false,
      signatureCount: 0,
      message: 'PDF does not contain digital signatures'
    };

    // ✅ ENHANCED: Multi-method signature detection
    const signaturePatterns = [
      /\/Sig\s+/g,                        // Standard AcroForm sig
      /\/Type\s*\/Sig\b/g,                // Typed signature objects
      /\/ByteRange\s*\[/g,                // ByteRange = signed content marker
      /\/Contents\s*<[0-9a-fA-F]{20,}/g, // Hex-encoded signature content
      /\/SubFilter\s*\/adbe\.pkcs7/gi,    // Adobe PKCS7 signatures
      /\/SubFilter\s*\/ETSI\.CAdES/gi,    // ETSI CAdES signatures
      /\/SubFilter\s*\/ETSI\.RFC3161/gi,  // Timestamp signatures
      /\/AcroForm[\s\S]{0,500}\/SigFlags/g // AcroForm with SigFlags
    ];

    // ✅ Also extract signer info if present
    const signerInfo = [];

    const signerPatterns = {
      signedBy: /\/Name\s*\(([^)]+)\)/,
      location: /\/Location\s*\(([^)]+)\)/,
      reason:   /\/Reason\s*\(([^)]+)\)/,
      contact:  /\/ContactInfo\s*\(([^)]+)\)/,
      date:     /\/M\s*\(([^)]+)\)/
    };

    // Find all /Sig dictionary blocks
    const sigBlocks = [...fileContent.matchAll(/\/Type\s*\/Sig([\s\S]{0,500}?)>>/g)];
    
    sigBlocks.forEach((block, i) => {
      const blockText = block[0];
      const info = { index: i };
      for (const [key, pattern] of Object.entries(signerPatterns)) {
        const m = blockText.match(pattern);
        if (m) info[key] = m[1].replace(/[\x00]/g, '').trim();
      }
      signerInfo.push(info);
    });

    // Count unique signature hits across all patterns
    let maxMatches = 0;
    for (const pattern of signaturePatterns) {
      const matches = fileContent.match(pattern);
      if (matches) maxMatches = Math.max(maxMatches, matches.length);
    }

    // ByteRange is the most reliable indicator
    const byteRangeMatches = fileContent.match(/\/ByteRange\s*\[/g);
    const sigCount = byteRangeMatches
      ? byteRangeMatches.length
      : (maxMatches > 0 ? maxMatches : 0);

    if (sigCount > 0) {
      verificationResult.isSigned = true;
      verificationResult.signatureCount = sigCount;
      verificationResult.message = `PDF contains ${sigCount} signature(s)`;
      verificationResult.signatures = Array(sigCount).fill(null).map((_, i) => ({
        index: i,
        isValid: null,
        message: 'Signature detected (validation pending)',
        ...(signerInfo[i] || {})
      }));
    }

    // ─── Tamper detection (unchanged) ───────────────────────────────────────
    const tamperDetails = {
      signatureTampered: false,
      deletionDetected: false,
      freedObjects: 0,
      hasIncrementalUpdates: false,
      eofCount: 0
    };

    const eofMatches = fileContent.match(/%%EOF/g);
    tamperDetails.eofCount = eofMatches ? eofMatches.length : 1;
    tamperDetails.hasIncrementalUpdates = tamperDetails.eofCount > 1;

    const freedMatches = fileContent.match(/\/Type\s*\/ObjStm.*?\/N\s+(\d+)/gs);
    if (freedMatches) {
      tamperDetails.deletionDetected = true;
      tamperDetails.freedObjects = freedMatches.length;
    }

    // ✅ FIXED: Only flag tampering if signed AND has suspicious updates
    // (don't flag unsigned PDFs as tampered)
    if (verificationResult.isSigned && tamperDetails.hasIncrementalUpdates) {
      tamperDetails.signatureTampered = true;
    }

    // ─── Risk scoring ────────────────────────────────────────────────────────
    const hasJavaScript    = /\/JavaScript|\/JS\s+/i.test(fileContent);
    const hasEmbeddedFiles = /\/EmbeddedFile/i.test(fileContent);
    const hasLayers        = /\/OC\s*<<|\/OCProperties/i.test(fileContent);

    let riskScore = 0;
    const riskFlags = [];

    if (hasJavaScript)    { riskScore += 30; riskFlags.push('⚠️ Contains JavaScript'); }
    if (hasEmbeddedFiles) { riskScore += 25; riskFlags.push('⚠️ Contains embedded files'); }
    if (tamperDetails.deletionDetected) {
      riskScore += 40;
      riskFlags.push('⚠️ Deleted objects detected');
    }
    if (tamperDetails.hasIncrementalUpdates && verificationResult.isSigned) {
      riskScore += 35;
      riskFlags.push('⚠️ Updates after signing');
    }
    if (tamperDetails.signatureTampered) {
      riskScore += 50;
      riskFlags.push('🚨 Signature tampering detected');
    }

    const riskLevel = riskScore >= 50 ? 'High' : riskScore >= 30 ? 'Medium' : 'Low';

    // ─── Page count ──────────────────────────────────────────────────────────
    const pageMatches = fileContent.match(/\/Type\s*\/Page[^s]/g);
    const pages = pageMatches ? pageMatches.length : 0;

    return {
      success: true,
      hash,
      pages,
      isSigned: verificationResult.isSigned,
      signatureCount: verificationResult.signatureCount,
      signatures: verificationResult.signatures,
      allValid: verificationResult.allValid,
      signatureMessage: verificationResult.message,
      tamperDetails,
      hasJavaScript,
      hasEmbeddedFiles,
      hasLayers,
      riskScore,
      riskLevel,
      flags: riskFlags.length > 0 ? riskFlags : ['✅ No threats detected'],
      metadata: extractMetadata(fileContent)
    };

  } catch (error) {
    console.error('PDF verification error:', error);
    return { success: false, error: error.message, isSigned: false, signatures: [] };
  }
};

// Extract metadata from PDF (unchanged)
function extractMetadata(fileContent) {
  const metadata = {};
  const patterns = {
    title:        /\/Title\s*\(([^)]+)\)/,
    author:       /\/Author\s*\(([^)]+)\)/,
    subject:      /\/Subject\s*\(([^)]+)\)/,
    creator:      /\/Creator\s*\(([^)]+)\)/,
    producer:     /\/Producer\s*\(([^)]+)\)/,
    creationDate: /\/CreationDate\s*\(([^)]+)\)/,
    modDate:      /\/ModDate\s*\(([^)]+)\)/
  };
  for (const [key, pattern] of Object.entries(patterns)) {
    const match = fileContent.match(pattern);
    if (match?.[1]) metadata[key] = match[1].replace(/[\x00]/g, '');
  }
  return metadata;
}

module.exports = { verifyPDFSignatures, extractMetadata };