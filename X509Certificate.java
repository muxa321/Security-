package x509;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;

/**
 * X.509 сертификатының өзіміздің моделі (UML-дегі X509Certificate).
 * Ескерту: JDK-да да java.security.cert.X509Certificate бар, сондықтан ол толық атпен жазылады.
 */
public class X509Certificate {
    private static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC);

    public final String subject;            // сертификат иесі
    public final String issuer;             // шығарушы (CA)
    public final BigInteger serialNumber;
    public final Instant validFrom;
    public final Instant validTo;
    public final PublicKey publicKey;
    public final byte[] signature;          // шығарушының цифрлық қолтаңбасы
    public final String signatureAlgorithm;
    private final java.security.cert.X509Certificate raw;   // тексеру үшін түпнұсқа JDK объектісі

    public X509Certificate(String subject, String issuer, BigInteger serialNumber, Instant validFrom,
                           Instant validTo, PublicKey publicKey, byte[] signature, String signatureAlgorithm,
                           java.security.cert.X509Certificate raw) {
        this.subject = subject;
        this.issuer = issuer;
        this.serialNumber = serialNumber;
        this.validFrom = validFrom;
        this.validTo = validTo;
        this.publicKey = publicKey;
        this.signature = signature;
        this.signatureAlgorithm = signatureAlgorithm;
        this.raw = raw;
    }

    public java.security.cert.X509Certificate getRaw() {
        return raw;
    }

    /** Subject пен issuer бірдей болса — сертификат өзіне өзі қол қойған. */
    public boolean isSelfSigned() {
        return raw.getSubjectX500Principal().equals(raw.getIssuerX500Principal());
    }

    public static String format(Instant time) {
        return FORMAT.format(time);
    }

    public String getSerialHex() {
        return HexFormat.ofDelimiter(":").withUpperCase().formatHex(serialNumber.toByteArray());
    }

    public String getKeyDescription() {
        if (publicKey instanceof RSAPublicKey) {
            return "RSA, " + ((RSAPublicKey) publicKey).getModulus().bitLength() + " bit";
        }
        if (publicKey instanceof ECPublicKey) {
            return "EC, " + ((ECPublicKey) publicKey).getParams().getOrder().bitLength() + " bit";
        }
        return publicKey.getAlgorithm();
    }

    public String getSignaturePreview() {
        int n = Math.min(16, signature.length);
        byte[] head = java.util.Arrays.copyOf(signature, n);
        return HexFormat.ofDelimiter(":").withUpperCase().formatHex(head) + "... (" + signature.length + " байт)";
    }

    public String getSha256Fingerprint() {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(raw.getEncoded());
            return HexFormat.ofDelimiter(":").withUpperCase().formatHex(digest);
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IllegalStateException("Fingerprint есептелмеді", e);
        }
    }

    @Override
    public String toString() {
        return subject + " (шығарған: " + issuer + ")";
    }
}
