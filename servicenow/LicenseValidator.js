/**
 * LicenseValidator - Script Include (Utility)
 *
 * Validates license keys signed with an X.509 certificate.
 * Token format: base64url(header).base64url(payload).base64url(signature)
 *
 * Usage:
 *   var lv = new LicenseValidator();
 *   var result = lv.validate(tokenString, 'my_certificate_name');
 *   if (result.valid) {
 *       gs.info('Licensed to: ' + result.payload.customer_name);
 *   } else {
 *       gs.error('License invalid: ' + result.error);
 *   }
 *
 * Prerequisites:
 *   - Upload certificate.crt to System Definition > Certificates (sys_certificate)
 *   - Set the "Name" field to a recognizable name (passed as certName)
 *   - Format: PEM, Type: Trust Store Cert
 */
var LicenseValidator = Class.create();
LicenseValidator.prototype = Object.extendsObject(AbstractAjaxProcessor, {

    type: 'LicenseValidator',

    // ── Public API ──────────────────────────────────────────────────────

    /**
     * Validate a license token against a named certificate in sys_certificate.
     * @param {string} token - The license token (header.payload.signature)
     * @param {string} certName - Name of the certificate record in sys_certificate
     * @returns {object} { valid: boolean, error: string|null, header: object|null, payload: object|null }
     */
    validate: function(token, certName) {
        try {
            // 1. Parse token
            var parts = this._splitToken(token);
            if (!parts) {
                return this._fail('Invalid token format. Expected 3 dot-separated parts.');
            }

            var header = this._jsonDecode(this._base64UrlDecode(parts.headerB64));
            if (!header) {
                return this._fail('Cannot decode header.');
            }

            var payload = this._jsonDecode(this._base64UrlDecode(parts.payloadB64));
            if (!payload) {
                return this._fail('Cannot decode payload.');
            }

            // 2. Check algorithm
            if (header.alg !== 'RS256') {
                return this._fail('Unsupported algorithm: ' + header.alg);
            }

            // 3. Load certificate from sys_certificate
            var certPem = this._loadCertificatePem(certName);
            if (!certPem) {
                return this._fail('Certificate not found: ' + certName);
            }

            var x509Cert = this._parseCertificate(certPem);
            if (!x509Cert) {
                return this._fail('Failed to parse certificate.');
            }

            // 4. Verify certificate fingerprint matches token header
            var certFingerprint = this._getCertFingerprint(x509Cert);
            var tokenFingerprint = header['x5t#S256'] || '';
            if (certFingerprint !== tokenFingerprint) {
                return this._fail('Certificate fingerprint mismatch. License was signed with a different certificate.');
            }

            // 5. Check certificate is not expired
            var expiryCheck = this._checkCertificateValidity(x509Cert);
            if (!expiryCheck.valid) {
                return this._fail(expiryCheck.error);
            }

            // 6. Verify RSA signature
            var signingInput = parts.headerB64 + '.' + parts.payloadB64;
            var signatureBytes = this._base64UrlDecodeToBytes(parts.signatureB64);
            var sigValid = this._verifySignature(x509Cert, signingInput, signatureBytes);
            if (!sigValid) {
                return this._fail('Signature verification failed. License data may be tampered.');
            }

            // All checks passed
            return {
                valid: true,
                error: null,
                header: header,
                payload: payload
            };

        } catch (e) {
            return this._fail('Unexpected error: ' + e.message);
        }
    },

    /**
     * AJAX-callable endpoint for client scripts.
     * Params via sysparm: sysparm_token, sysparm_cert_name
     */
    validateAjax: function() {
        var token = this.getParameter('sysparm_token');
        var certName = this.getParameter('sysparm_cert_name');
        var result = this.validate(token, certName);
        return JSON.stringify(result);
    },

    // ── Token Parsing ───────────────────────────────────────────────────

    _splitToken: function(token) {
        if (!token || typeof token !== 'string') {
            return null;
        }
        var parts = token.trim().split('.');
        if (parts.length !== 3) {
            return null;
        }
        return {
            headerB64: parts[0],
            payloadB64: parts[1],
            signatureB64: parts[2]
        };
    },

    // ── Base64URL ───────────────────────────────────────────────────────

    /**
     * Decode base64url string to a regular string (UTF-8).
     */
    _base64UrlDecode: function(str) {
        // Convert base64url to standard base64
        var base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        // Restore padding
        var padLen = (4 - (base64.length % 4)) % 4;
        for (var i = 0; i < padLen; i++) {
            base64 += '=';
        }
        var Decoder = Packages.java.util.Base64.getDecoder();
        var bytes = Decoder.decode(base64);
        return new Packages.java.lang.String(bytes, 'UTF-8') + '';
    },

    /**
     * Decode base64url string to a Java byte array (for signature).
     */
    _base64UrlDecodeToBytes: function(str) {
        var base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        var padLen = (4 - (base64.length % 4)) % 4;
        for (var i = 0; i < padLen; i++) {
            base64 += '=';
        }
        var Decoder = Packages.java.util.Base64.getDecoder();
        return Decoder.decode(base64);
    },

    // ── JSON ────────────────────────────────────────────────────────────

    _jsonDecode: function(str) {
        try {
            return JSON.parse(str);
        } catch (e) {
            return null;
        }
    },

    // ── Certificate Operations ──────────────────────────────────────────

    /**
     * Load PEM string from sys_certificate by name.
     */
    _loadCertificatePem: function(certName) {
        var gr = new GlideRecord('sys_certificate');
        gr.addQuery('name', certName);
        gr.addQuery('type', 'trust_store_cert');
        gr.setLimit(1);
        gr.query();
        if (gr.next()) {
            return gr.getValue('pem_certificate') || '';
        }
        return null;
    },

    /**
     * Parse a PEM certificate string into a Java X509Certificate object.
     */
    _parseCertificate: function(pem) {
        try {
            var CertificateFactory = Packages.java.security.cert.CertificateFactory;
            var ByteArrayInputStream = Packages.java.io.ByteArrayInputStream;

            var pemBytes = new Packages.java.lang.String(pem).getBytes('UTF-8');
            var stream = new ByteArrayInputStream(pemBytes);
            var factory = CertificateFactory.getInstance('X.509');
            return factory.generateCertificate(stream);
        } catch (e) {
            gs.error('LicenseValidator: Failed to parse certificate - ' + e.message);
            return null;
        }
    },

    /**
     * SHA-256 fingerprint of the DER-encoded certificate (hex, lowercase).
     */
    _getCertFingerprint: function(x509Cert) {
        var MessageDigest = Packages.java.security.MessageDigest;
        var derBytes = x509Cert.getEncoded();
        var digest = MessageDigest.getInstance('SHA-256');
        var hashBytes = digest.digest(derBytes);
        return this._bytesToHex(hashBytes);
    },

    /**
     * Check if the certificate is currently valid (not expired, not before start).
     */
    _checkCertificateValidity: function(x509Cert) {
        try {
            x509Cert.checkValidity(); // throws if invalid
            return { valid: true };
        } catch (e) {
            var notBefore = x509Cert.getNotBefore();
            var notAfter = x509Cert.getNotAfter();
            return {
                valid: false,
                error: 'Certificate is not valid. Valid from ' + notBefore + ' to ' + notAfter + '.'
            };
        }
    },

    // ── Signature Verification ──────────────────────────────────────────

    /**
     * Verify RS256 (RSASSA-PKCS1-v1_5 + SHA-256) signature.
     */
    _verifySignature: function(x509Cert, signingInput, signatureBytes) {
        try {
            var Signature = Packages.java.security.Signature;
            var verifier = Signature.getInstance('SHA256withRSA');
            verifier.initVerify(x509Cert.getPublicKey());
            verifier.update(new Packages.java.lang.String(signingInput).getBytes('UTF-8'));
            return verifier.verify(signatureBytes);
        } catch (e) {
            gs.error('LicenseValidator: Signature verification error - ' + e.message);
            return false;
        }
    },

    // ── Helpers ─────────────────────────────────────────────────────────

    _bytesToHex: function(bytes) {
        var hex = '';
        for (var i = 0; i < bytes.length; i++) {
            var b = bytes[i] & 0xFF;
            if (b < 16) {
                hex += '0';
            }
            hex += b.toString(16);
        }
        return hex;
    },

    _fail: function(error) {
        return {
            valid: false,
            error: error,
            header: null,
            payload: null
        };
    }
});
