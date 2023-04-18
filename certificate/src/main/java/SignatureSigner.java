import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;

public class SignatureSigner {

    public byte[] signText(String text, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(privateKey);
            signature.update(text.getBytes(StandardCharsets.UTF_8));
            return signature.sign();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
