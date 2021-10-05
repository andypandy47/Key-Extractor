const base64 = require("js-base64");
const sha256 = require("sha256");
const x509 = require("js-x509-utils");
const jwkToPem = require("jwk-to-pem");
const readline = require("readline");

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

const certPrefix = "-----BEGIN CERTIFICATE-----\n";
const certPostfix = "-----END CERTIFICATE-----";
const pubKeyPrefix = "-----BEGIN PUBLIC KEY-----\n";
const pubKeyPostfix = "-----END PUBLIC KEY-----";

const containsCertTags = (cert) => {
    return (cert.includes(certPrefix) || cert.includes(certPostfix));
}

const removeCertTags = (cert) => {
    return cert.replace(certPrefix, "").replace(certPostfix, "");
}

const addCertTags = (cert) => {
    return certPrefix + cert.match(/.{0,64}/g).join("\n") + certPostfix;
}

const removeKeyTags = (key) => {
    return key.replace(pubKeyPrefix, "").replace(pubKeyPostfix, "");
}

const getKid = (cert) => {
    if (containsCertTags(cert)) {
        cert = removeCertTags(cert);
    }

    const decodedCert = base64.toUint8Array(cert);

    const hashBuffer = sha256(decodedCert, { asBytes: true });

    const truncatedHash = hashBuffer.slice(0, 8);

    const encodedKid = base64.encode(truncatedHash);

    return encodedKid;
}

const getPublicKey = async (cert) => {
    if (!containsCertTags(cert)) {
        cert = addCertTags(cert);
    }

    const jwk = await x509.toJwk(cert, "pem");

    const pemKey = jwkToPem(jwk);

    return removeKeyTags(pemKey);
}

const printKeyValue = async (cert) => {
    const kid = getKid(cert);
    const publicKey = await getPublicKey(cert);
    
    console.log("kid:");
    console.log(`${kid}\n`);
    console.log("publicKey:");
    console.log(`${publicKey}`);
}   

const testCert_01 =
"MIIDIjCCAsigAwIBAgIEYTtGPDAKBggqhkjOPQQDAjBWMQswCQYDVQQGEwJHQjEUMBIGA1UEChMLTkhTIERpZ2l0YWwxFjAUBgNVBAsTDVByZVByb2R1Y3Rpb24xGTAXBgNVBAMTEEVuZ2xhbmQgRENDIENTQ0EwHhcNMjEwOTI3MTYwMjU3WhcNMjMwOTI3MTYzMjU3WjB5MQswCQYDVQQGEwJHQjEUMBIGA1UEChMLTkhTIERpZ2l0YWwxGDAWBgNVBAgMD0VuZ2xhbmQgJiBXYWxlczEWMBQGA1UECxMNUHJlUHJvZHVjdGlvbjEiMCAGA1UEAwwZRFNDX0RDQ19HQl9QUkVQUk9EX0VOR18wMjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCXmqBChblrCrzJ/8ISbsKaXQdmBx1REUi1YMUgHOJNhFPzbQvL0sr5gPFby7r4e2y+c1mLOqO5KrF6Zkm9y+A+jggFfMIIBWzAOBgNVHQ8BAf8EBAMCB4AweAYDVR0SBHEwb4EPcGtpQG5oc3gubmhzLnVrgkpodHRwczovL3d3dy5uaHN4Lm5ocy51ay9rZXktdG9vbHMtYW5kLWluZm8vcHVibGljLWtleS1pbmZyYXN0cnVjdHVyZXMvY3NjYaQQMA4xDDAKBgNVBAcMA0dCUjBiBgNVHR8EWzBZMFegVaBThlFodHRwczovL3N0YWdlLmNvdmlkLXN0YXR1cy5zZXJ2aWNlLm5oc3gubmhzLnVrL0NSTC9QcmVwX05hdGlvbmFsX2VIZWFsdGhfQ1NDQS5jcmwwKwYDVR0QBCQwIoAPMjAyMTA5MjcxNjAyNTdagQ8yMDIyMDMyOTA0MzI1N1owHwYDVR0jBBgwFoAUzJ2RzbC6KMpTliQ6/3OUUj+KlHowHQYDVR0OBBYEFHcd0jk1B6CdFFCkW+v0P5ttY61WMAoGCCqGSM49BAMCA0gAMEUCIQCJ9zyXNHEZLVfXkIl8MqauPGDb/NDalfcntgEAt/y6lwIgcGWI5vIOd6YJURuSSND4WVacewFlb4EPWnNKSXMdXkQ=";

printKeyValue(testCert_01);