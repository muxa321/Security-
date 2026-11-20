package x509;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Сертификат тізбегін (leaf -> intermediate -> root) сенімді түбір сертификатқа дейін тексереді.
 * Сенімді түбірлер: JDK-ның стандартты тізімі (cacerts) + addTrustedRoot() арқылы қосылғандар.
 */
public class ChainValidator {
    private final Set<TrustAnchor> anchors = new HashSet<>();

    public ChainValidator() {
        loadDefaultTrust();
    }

    private void loadDefaultTrust() {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager) {
                    for (java.security.cert.X509Certificate c : ((X509TrustManager) tm).getAcceptedIssuers()) {
                        anchors.add(new TrustAnchor(c, null));
                    }
                }
            }
        } catch (GeneralSecurityException e) {
            // стандартты тізім оқылмаса — тек қолмен қосылған түбірлер жұмыс істейді
        }
    }

    public void addTrustedRoot(java.security.cert.X509Certificate root) {
        anchors.add(new TrustAnchor(root, null));
    }

    public int getTrustAnchorCount() {
        return anchors.size();
    }

    public ValidationResult validateChain(List<X509Certificate> chain) {
        String name = "Сертификат тізбегі";
        if (chain.isEmpty()) {
            return ValidationResult.invalid(name, "тізбек бос");
        }
        if (anchors.isEmpty()) {
            return ValidationResult.warning(name, "сенімді түбір сертификаттар тізімі бос");
        }

        List<Certificate> path = new ArrayList<>();
        for (X509Certificate c : chain) {
            path.add(c.getRaw());
        }

        // Соңында түбір (self-signed) тұрса, ол — сенімді нүктенің өзі, жолға кірмейді.
        X509Certificate last = chain.get(chain.size() - 1);
        if (last.isSelfSigned()) {
            path.remove(path.size() - 1);
            if (!isTrusted(last)) {
                return ValidationResult.invalid(name, "түбір сертификат сенімді тізімде жоқ: " + last.subject);
            }
            if (path.isEmpty()) {
                return ValidationResult.valid(name, "сертификат сенімді түбір тізімінде бар");
            }
        }

        try {
            CertPath certPath = CertificateFactory.getInstance("X.509").generateCertPath(path);
            PKIXParameters params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false);   // CRL/OCSP желіні қажет етеді, оқу жобасында өшірілген
            PKIXCertPathValidatorResult result =
                    (PKIXCertPathValidatorResult) CertPathValidator.getInstance("PKIX").validate(certPath, params);
            String root = result.getTrustAnchor().getTrustedCert() != null
                    ? result.getTrustAnchor().getTrustedCert().getSubjectX500Principal().getName()
                    : result.getTrustAnchor().getCAName();
            return ValidationResult.valid(name, "сенімді түбірге дейін жарамды (" + root + ")");
        } catch (CertPathValidatorException e) {
            return ValidationResult.invalid(name, explain(e));
        } catch (GeneralSecurityException e) {
            return ValidationResult.invalid(name, "тізбекті тексеру мүмкін болмады: " + e.getMessage());
        }
    }

    private boolean isTrusted(X509Certificate cert) {
        for (TrustAnchor ta : anchors) {
            if (cert.getRaw().equals(ta.getTrustedCert())) {
                return true;
            }
        }
        return false;
    }

    private String explain(CertPathValidatorException e) {
        String where = e.getIndex() >= 0 ? " (тізбектегі " + (e.getIndex() + 1) + "-сертификат)" : "";
        CertPathValidatorException.Reason reason = e.getReason();
        if (reason == CertPathValidatorException.BasicReason.EXPIRED) {
            return "сертификаттың мерзімі өткен" + where;
        }
        if (reason == CertPathValidatorException.BasicReason.NOT_YET_VALID) {
            return "сертификат әлі күшіне енбеген" + where;
        }
        if (reason == CertPathValidatorException.BasicReason.INVALID_SIGNATURE) {
            return "қолтаңба сәйкес емес" + where;
        }
        String msg = String.valueOf(e.getMessage());
        if (msg.contains("does not chain with any of the trust anchors")) {
            return "тізбек сенімді түбір сертификатқа жетпейді (түбір сенімді тізімде жоқ)";
        }
        return msg + where;
    }
}
