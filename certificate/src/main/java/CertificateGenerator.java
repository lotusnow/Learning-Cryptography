
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.time.LocalDate;
import java.time.ZoneId;


public class CertificateGenerator {

    public Pair<X509Certificate, PrivateKey> createCertificate() {
        try {
            X500Name issuer = new X500Name("CN=Issuer, O=Example Company, C=US");
            X500Name subject = new X500Name("CN=Subject, O=Example Company, C=US");
            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
            Date notBefore = Date.from(LocalDate.now().atStartOfDay(ZoneId.systemDefault()).toInstant());
            Date notAfter = Date.from(LocalDate.now().plusYears(1).atStartOfDay(ZoneId.systemDefault()).toInstant());
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(256);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                    issuer,
                    serialNumber,
                    notBefore,
                    notAfter,
                    subject,
                    keyPair.getPublic()
            );

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                    .build(keyPair.getPrivate());

            X509CertificateHolder certificateHolder = certificateBuilder.build(signer);

            return Pair.of(new JcaX509CertificateConverter()
                    .setProvider(new BouncyCastleProvider())
                    .getCertificate(certificateHolder), keyPair.getPrivate());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
