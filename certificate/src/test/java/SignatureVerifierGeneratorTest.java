import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class SignatureVerifierGeneratorTest {

    @Test
    void createCert() {
        CertificateGenerator certificateGenerator = new CertificateGenerator();
        Pair<X509Certificate, PrivateKey> response = certificateGenerator.createCertificate();
        System.out.println(response.getLeft());
    }

}