package x509;

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

/**
 * Басты класс: файлды оқиды, барлық тексеруді жүргізіп, нәтижені көрсетеді.
 * Реті: parser -> validator (мерзім) -> signature verifier -> chain validator -> displayResult.
 */
public class CertificateAnalyzer {
    private final CertificateParser parser = new CertificateParser();
    private final CertificateValidator validator = new CertificateValidator();
    private final SignatureVerifier signatureVerifier = new SignatureVerifier();
    private final ChainValidator chainValidator = new ChainValidator();

    private Path file;
    private List<X509Certificate> chain = new ArrayList<>();
    private final List<ValidationResult> results = new ArrayList<>();
    private ValidationResult verdict;

    /** Қосымша сенімді түбір сертификатты файлдан қосады (мысалы, өз CA-ң). */
    public void addTrustedRoot(Path rootFile) throws IOException, CertificateException {
        for (java.security.cert.X509Certificate c : parser.parseCertificate(rootFile)) {
            chainValidator.addTrustedRoot(c);
        }
    }

    /** Файлдағы сертификатты (және оның тізбегін) талдайды. Қорытынды нәтижені қайтарады. */
    public ValidationResult analyzeCertificate(Path certFile) {
        this.file = certFile;
        chain = new ArrayList<>();
        results.clear();
        final String name = "Қорытынды";

        // 1. Талдау (parse + extractFields)
        try {
            for (java.security.cert.X509Certificate raw : parser.parseCertificate(certFile)) {
                chain.add(parser.extractFields(raw));
            }
        } catch (IOException e) {
            verdict = ValidationResult.invalid(name, "файлды оқу мүмкін болмады: " + e.getMessage());
            return verdict;
        } catch (CertificateException e) {
            verdict = ValidationResult.invalid(name, "формат қате, X.509 сертификат емес: " + e.getMessage());
            return verdict;
        }

        X509Certificate target = chain.get(0);

        // 2. Мерзім
        results.add(validator.checkValidity(target));
        results.add(validator.checkExpiration(target));

        // 3. Қолтаңба: шығарушыны файлдағы тізбектен іздейміз
        X509Certificate issuer = null;
        if (!target.isSelfSigned()) {
            for (X509Certificate c : chain) {
                if (c != target && c.getRaw().getSubjectX500Principal()
                        .equals(target.getRaw().getIssuerX500Principal())) {
                    issuer = c;
                    break;
                }
            }
        }
        results.add(signatureVerifier.verifySignature(target, issuer));

        // 4. Тізбек
        results.add(chainValidator.validateChain(chain));

        verdict = ValidationResult.overall(name, results);
        return verdict;
    }

    public ValidationResult getVerdict() {
        return verdict;
    }

    public List<ValidationResult> getResults() {
        return results;
    }

    /** Талдау нәтижесін экранға шығарады. */
    public void displayResult() {
        System.out.println("============================================================");
        System.out.println("Файл: " + file);
        if (chain.isEmpty()) {
            System.out.println(verdict.getResult());
            return;
        }
        X509Certificate c = chain.get(0);
        System.out.println("Сертификат өрістері:");
        System.out.println("  Subject (иесі)        : " + c.subject);
        System.out.println("  Issuer (шығарушы)     : " + c.issuer);
        System.out.println("  Serial number         : " + c.getSerialHex());
        System.out.println("  Valid from            : " + X509Certificate.format(c.validFrom));
        System.out.println("  Valid to              : " + X509Certificate.format(c.validTo));
        System.out.println("  Public key            : " + c.getKeyDescription());
        System.out.println("  Signature algorithm   : " + c.signatureAlgorithm);
        System.out.println("  Signature             : " + c.getSignaturePreview());
        System.out.println("  SHA-256 fingerprint   : " + c.getSha256Fingerprint());
        System.out.println("  Self-signed           : " + (c.isSelfSigned() ? "иә" : "жоқ"));
        if (chain.size() > 1) {
            System.out.println("Файлдағы тізбек (" + chain.size() + " сертификат):");
            for (int i = 0; i < chain.size(); i++) {
                System.out.println("  " + (i + 1) + ") " + chain.get(i).subject);
            }
        }
        System.out.println("Тексеру нәтижелері:");
        for (ValidationResult r : results) {
            System.out.println("  " + r.getResult());
        }
        System.out.println("НӘТИЖЕ: " + verdict.getStatus() + " — " + verdictText());
    }

    private String verdictText() {
        switch (verdict.getStatus()) {
            case ValidationResult.VALID:
                return "сертификат сенімді және жарамды";
            case ValidationResult.WARNING:
                return "сертификатта ескертулер бар";
            default:
                return "сертификатқа сенуге болмайды";
        }
    }
}
