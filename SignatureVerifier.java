package x509;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SignatureException;

/** Сертификаттағы цифрлық қолтаңбаны шығарушының ашық кілтімен тексереді. */
public class SignatureVerifier {

    /**
     * @param cert   тексерілетін сертификат
     * @param issuer шығарушы сертификаты (CA); self-signed болса null беруге болады
     */
    public ValidationResult verifySignature(X509Certificate cert, X509Certificate issuer) {
        String name = "Цифрлық қолтаңба";
        PublicKey key;
        String by;
        if (issuer != null) {
            key = issuer.publicKey;
            by = "шығарушы кілтімен: " + issuer.subject;
        } else if (cert.isSelfSigned()) {
            key = cert.publicKey;
            by = "өз кілтімен (self-signed)";
        } else {
            return ValidationResult.warning(name,
                    "шығарушы сертификаты берілмеген, қолтаңбаны тексеру мүмкін емес");
        }
        try {
            cert.getRaw().verify(key);
            return ValidationResult.valid(name, "сәйкес, " + by + " [" + cert.signatureAlgorithm + "]");
        } catch (SignatureException e) {
            return ValidationResult.invalid(name,
                    "қолтаңба сәйкес емес — сертификат өзгертілген немесе басқа кілтпен қол қойылған");
        } catch (GeneralSecurityException e) {
            return ValidationResult.invalid(name, "тексеру мүмкін болмады: " + e.getMessage());
        }
    }
}
