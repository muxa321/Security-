package x509;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.security.auth.x500.X500Principal;

/** Файлдан X.509 сертификатты оқиды (PEM немесе DER) және өрістерін бөліп алады. */
public class CertificateParser {

    /** Файлды талдап, ішіндегі барлық сертификатты қайтарады (PEM файлда тізбек болуы мүмкін). */
    public List<java.security.cert.X509Certificate> parseCertificate(Path file)
            throws IOException, CertificateException {
        byte[] data = Files.readAllBytes(file);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> found = factory.generateCertificates(new ByteArrayInputStream(data));

        List<java.security.cert.X509Certificate> result = new ArrayList<>();
        for (Certificate c : found) {
            if (c instanceof java.security.cert.X509Certificate) {
                result.add((java.security.cert.X509Certificate) c);
            }
        }
        if (result.isEmpty()) {
            throw new CertificateException("Файлда X.509 сертификат табылмады");
        }
        return result;
    }

    /** JDK сертификатынан өзіміздің X509Certificate моделін құрады. */
    public X509Certificate extractFields(java.security.cert.X509Certificate raw) {
        return new X509Certificate(
                raw.getSubjectX500Principal().getName(X500Principal.RFC1779),
                raw.getIssuerX500Principal().getName(X500Principal.RFC1779),
                raw.getSerialNumber(),
                Instant.ofEpochMilli(raw.getNotBefore().getTime()),
                Instant.ofEpochMilli(raw.getNotAfter().getTime()),
                raw.getPublicKey(),
                raw.getSignature(),
                raw.getSigAlgName(),
                raw);
    }
}
