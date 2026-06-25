const fs = require('fs');
const path = require('path');
const { verify } = require('@ninja-labs/verify-pdf');
const crypto = require('crypto');

// Comprehensive PDF verification using @ninja-labs/verify-pdf
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

    // Use @ninja-labs/verify-pdf for proper verification
    let verificationResult = {
      isSigned: false,
      signatures: [],
      allValid: false,
      signatureCount: 0,
      message: 'PDF does not contain digital signatures'
    };

    try {
      // Call @ninja-labs/verify-pdf
      const result = await verify(fileBuffer);

      if (result && result.signatures && result.signatures.length > 0) {
        verificationResult.isSigned = true;
        verificationResult.signatureCount = result.signatures.length;
        verificationResult.signatures = result.signatures.map((sig, index) => ({
          index: index,
          isValid: sig.isValid,
          certificate: sig.certificate,
          subject: sig.subject,
          issuer: sig.issuer,
          validFrom: sig.validFrom,
          validTo: sig.validTo,
          message: sig.message || (sig.isValid ? 'Valid signature' : 'Invalid signature')
        }));

        // Check if all signatures are valid
        verificationResult.allValid = result.signatures.every(sig => sig.isValid);
        verificationResult.message = `PDF contains ${result.signatures.length} signature(s). ${
          verificationResult.allValid ? 'All signatures are valid.' : 'Some signatures are invalid.'
        }`;
      }
    } catch (verifyError) {
      console.warn('Verification library error (falling back to basic check):', verifyError.message);
      
      // Fallback: basic signature detection
      const sigMatches = fileContent.match(/\/Sig\s+/g);
      if (sigMatches && sigMatches.length > 0) {
        verificationResult.isSigned = true;
        verificationResult.signatureCount = sigMatches.length;
        verificationResult.message = `PDF contains ${sigMatches.length} signature(s) (basic detection)`;
        verificationResult.signatures = Array(sigMatches.length).fill(null).map((_, i) => ({
          index: i,
          isValid: null,
          message: 'Could not verify (basic detection only)'
        }));
      }
    }

    // Detect tampering indicators
    const tamperDetails = {
      signatureTampered: false,
      deletionDetected: false,
      freedObjects: 0,
      hasIncrementalUpdates: false,
      eofCount: 0
    };

    // Check for incremental updates (multiple %%EOF)
    const eofMatches = fileContent.match(/%%EOF/g);
    tamperDetails.eofCount = eofMatches ? eofMatches.length : 1;
    tamperDetails.hasIncrementalUpdates = tamperDetails.eofCount > 1;

    // Check for freed objects
    const freedMatches = fileContent.match(/\/Type\s*\/ObjStm.*?\/N\s+(\d+)/gs);
    if (freedMatches) {
      tamperDetails.deletionDetected = true;
      tamperDetails.freedObjects = freedMatches.length;
    }

    // Check signature validity
    if (verificationResult.isSigned && !verificationResult.allValid) {
      tamperDetails.signatureTampered = true;
    }

    // Analyze content for risks
    const hasJavaScript = /\/JavaScript|\/JS\s+/i.test(fileContent);
    const hasEmbeddedFiles = /\/EmbeddedFile/i.test(fileContent);
    const hasLayers = /\/OC\s*<<|\/OCProperties/i.test(fileContent);

    // Calculate risk level
    let riskScore = 0;
    let riskLevel = 'Low';
    const riskFlags = [];

    if (hasJavaScript) {
      riskScore += 30;
      riskFlags.push('⚠️ Contains JavaScript');
    }
    if (hasEmbeddedFiles) {
      riskScore += 25;
      riskFlags.push('⚠️ Contains embedded files');
    }
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

    if (riskScore >= 50) {
      riskLevel = 'High';
    } else if (riskScore >= 30) {
      riskLevel = 'Medium';
    } else {
      riskLevel = 'Low';
    }

    // Count pages (basic extraction)
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
    return {
      success: false,
      error: error.message,
      isSigned: false,
      signatures: []
    };
  }
};

// Extract metadata from PDF
function extractMetadata(fileContent) {
  const metadata = {};

  // Extract common metadata fields
  const patterns = {
    title: /\/Title\s*\(([^)]+)\)/,
    author: /\/Author\s*\(([^)]+)\)/,
    subject: /\/Subject\s*\(([^)]+)\)/,
    creator: /\/Creator\s*\(([^)]+)\)/,
    producer: /\/Producer\s*\(([^)]+)\)/,
    creationDate: /\/CreationDate\s*\(([^)]+)\)/,
    modDate: /\/ModDate\s*\(([^)]+)\)/
  };

  for (const [key, pattern] of Object.entries(patterns)) {
    const match = fileContent.match(pattern);
    if (match && match[1]) {
      metadata[key] = match[1].replace(/[\x00]/g, '');
    }
  }

  return metadata;
}

module.exports = { 
  verifyPDFSignatures,
  extractMetadata
};