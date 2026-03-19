/**
 * LicenseValidatorOOB - Script Include (Utility)
 *
 * Validates license keys using ServiceNow OOB APIs only (no Java Packages).
 * Token format: base64url(header).base64url(payload).base64url(signature)
 *
 * Usage:
 *   var lv = new LicenseValidatorOOB();
 *   var result = lv.validate(tokenString, 'my_certificate_sys_id');
 *   if (result.valid) {
 *       gs.info('Licensed to: ' + result.payload.customer_name);
 *   } else {
 *       gs.error('License invalid: ' + result.error);
 *   }
 *
 * Prerequisites:
 *   - Upload certificate.crt to System Definition > Certificates (sys_certificate)
 *   - Type: Trust Store Cert
 *   - Pass the sys_id of that certificate record
 */
var LicenseValidatorOOB = Class.create();
LicenseValidatorOOB.prototype = Object.extendsObject(AbstractAjaxProcessor, {

    type: 'LicenseValidatorOOB',

    // ── Public API ──────────────────────────────────────────────────────

    /**
     * Validate a license token against a certificate in sys_certificate.
     * @param {string} token - The license token (header.payload.signature)
     * @param {string} certSysId - sys_id of the certificate record in sys_certificate
     * @returns {object} { valid, error, header, payload }
     */
    validate: function(token, certSysId) {
        try {
            // 1. Parse token into 3 parts
            var parts = this._splitToken(token);
            if (!parts) {
                return this._fail('Invalid token format. Expected 3 dot-separated parts.');
            }

            // 2. Decode header and payload
            var header = this._jsonDecode(this._base64UrlToString(parts.headerB64));
            if (!header) {
                return this._fail('Cannot decode header.');
            }

            var payload = this._jsonDecode(this._base64UrlToString(parts.payloadB64));
            if (!payload) {
                return this._fail('Cannot decode payload.');
            }

            // 3. Check algorithm
            if (header.alg !== 'RS256') {
                return this._fail('Unsupported algorithm: ' + header.alg);
            }

            // 4. Load certificate record
            var certGr = new GlideRecord('sys_certificate');
            if (!certGr.get(certSysId)) {
                return this._fail('Certificate record not found: ' + certSysId);
            }

            // 5. Verify certificate fingerprint matches token
            var certPem = certGr.getValue('pem_certificate') || '';
            var certFingerprint = this._getCertFingerprint(certPem);
            var tokenFingerprint = header['x5t#S256'] || '';
            if (certFingerprint !== tokenFingerprint) {
                return this._fail('Certificate fingerprint mismatch. License was signed with a different certificate.');
            }

            // 6. Check certificate expiry from header dates
            var now = new GlideDateTime();
            var notAfter = new GlideDateTime(header.not_after);
            var notBefore = new GlideDateTime(header.not_before);
            if (now.compareTo(notBefore) < 0 || now.compareTo(notAfter) > 0) {
                return this._fail('Certificate expired. Valid from ' + header.not_before + ' to ' + header.not_after);
            }

            // 7. Verify RSA SHA-256 signature using CertificateEncryption
            var signingInput = parts.headerB64 + '.' + parts.payloadB64;
            var signatureStdB64 = this._base64UrlToBase64(parts.signatureB64);

            var ce = new CertificateEncryption();
            var isValid = ce.verifySignature(signingInput, signatureStdB64, certSysId, 'SHA-256');

            if (!isValid) {
                return this._fail('Signature verification failed. License data may be tampered.');
            }

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
     * AJAX endpoint for client scripts.
     * sysparm_token, sysparm_cert_sys_id
     */
    validateAjax: function() {
        var token = this.getParameter('sysparm_token');
        var certSysId = this.getParameter('sysparm_cert_sys_id');
        var result = this.validate(token, certSysId);
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
     * Convert base64url to standard base64.
     */
    _base64UrlToBase64: function(str) {
        var base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        var padLen = (4 - (base64.length % 4)) % 4;
        for (var i = 0; i < padLen; i++) {
            base64 += '=';
        }
        return base64;
    },

    /**
     * Decode base64url string to UTF-8 string.
     * Works in both global and scoped apps.
     */
    _base64UrlToString: function(str) {
        var base64 = this._base64UrlToBase64(str);
        return this._b64Decode(base64);
    },

    /**
     * Base64 decode — uses gs.base64Decode() which works in scoped apps.
     */
    _b64Decode: function(base64) {
        return gs.base64Decode(base64);
    },

    // ── Hashing / Fingerprint ───────────────────────────────────────────

    /**
     * SHA-256 fingerprint of the DER-encoded certificate (hex, lowercase).
     * Strips PEM headers, decodes base64 to get DER, then hashes.
     */
    _getCertFingerprint: function(pem) {
        var derB64 = pem
            .replace(/-----BEGIN CERTIFICATE-----/g, '')
            .replace(/-----END CERTIFICATE-----/g, '')
            .replace(/\s+/g, '');

        var gd = new GlideDigest();
        var derString = this._b64Decode(derB64);
        return gd.getSHA256Hex(derString);
    },

    // ── Helpers ─────────────────────────────────────────────────────────

    _jsonDecode: function(str) {
        try {
            return JSON.parse(str);
        } catch (e) {
            return null;
        }
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
