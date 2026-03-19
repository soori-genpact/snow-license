var LicenseValidatorModule = Class.create();
LicenseValidatorModule.prototype = Object.extendsObject(global.AbstractAjaxProcessor, {

    type: 'LicenseValidatorModule',
  
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
            gs.info('Step 1 - Token has ' + (parts ? '3' : '0') + ' parts: ' + (parts ? 'OK' : 'FAIL'));
            if (!parts) {
                return this._fail('Invalid token format. Expected 3 dot-separated parts.');
            }

            // 2. Decode header and payload
            var headerStr = this._base64UrlToString(parts.headerB64);
            var header = this._jsonDecode(headerStr);
            gs.info('Step 2 - Header: ' + headerStr);
            if (!header) {
                return this._fail('Cannot decode header.');
            }

            var payloadStr = this._base64UrlToString(parts.payloadB64);
            var payload = this._jsonDecode(payloadStr);
            gs.info('Step 3 - Payload: ' + payloadStr);
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
                gs.info('Step 4 - FAIL: Certificate not found');
                return this._fail('Certificate record not found: ' + certSysId);
            }
            gs.info('Step 4 - Certificate loaded: ' + certGr.getValue('name'));

            // 5. Verify certificate fingerprint matches token
            var certPem = certGr.getValue('pem_certificate') || '';
            var certFingerprint = this._getCertFingerprint(certPem);
            var tokenFingerprint = header['x5t#S256'] || '';
            gs.info('Step 5 - Cert FP : ' + certFingerprint);
            gs.info('Step 5 - Token FP: ' + tokenFingerprint);
            gs.info('Step 5 - Match: ' + (certFingerprint.toLowerCase() === tokenFingerprint.toLowerCase() ? 'OK' : 'FAIL'));
            if (certFingerprint.toLowerCase() !== tokenFingerprint.toLowerCase()) {
                return this._fail('Certificate fingerprint mismatch. License was signed with a different certificate.');
            }

            // 6. Check certificate expiry from header dates
            var now = new GlideDateTime();
            var notAfter = new GlideDateTime(header.not_after);
            var notBefore = new GlideDateTime(header.not_before);
            var expired = (now.compareTo(notBefore) < 0 || now.compareTo(notAfter) > 0);
            gs.info('Step 6 - Cert valid: ' + (!expired ? 'OK' : 'EXPIRED'));
            if (expired) {
                return this._fail('Certificate expired. Valid from ' + header.not_before + ' to ' + header.not_after);
            }

            return {
                valid: true,
                error: null,
                header: header,
                payload: payload
            };

        } catch (e) {
            gs.info('ERROR: ' + e.message);
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
     * SHA-256 fingerprint of the certificate's base64-encoded DER (hex).
     * Strips PEM headers/whitespace, then hashes the base64 DER string directly.
     */
    _getCertFingerprint: function(pem) {
        var derB64 = pem
            .replace(/-----BEGIN CERTIFICATE-----/g, '')
            .replace(/-----END CERTIFICATE-----/g, '')
            .replace(/\s+/g, '');

        var gd = new GlideDigest();
        return gd.getSHA256Hex(derB64);
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