import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

public class SignatureVerifier {

    public boolean verifySignature(String text, byte[] signatureBytes, X509Certificate certificate) {
        try {
            PublicKey publicKey = certificate.getPublicKey();
            Signature signature = Signature.getInstance("SHA256withECDSA");

            signature.initVerify(publicKey);
            signature.update(text.getBytes(StandardCharsets.UTF_8));
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

