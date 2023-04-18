import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

class SignatureVerifierTest {

    @Test
    void verifyText() {
        CertificateGenerator certificateGenerator = new CertificateGenerator();
        SignatureSigner signatureSigner = new SignatureSigner();
        SignatureVerifier signatureVerifier = new SignatureVerifier();

        Pair<X509Certificate, PrivateKey> response = certificateGenerator.createCertificate();
        byte[] signed = signatureSigner.signText("hahahoho", response.getRight());
        assertThat(signatureVerifier.verifySignature("hahaha", signed, response.getLeft())).isFalse();
        assertThat(signatureVerifier.verifySignature("hahahoho", signed, response.getLeft())).isTrue();
    }
}