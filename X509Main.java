package x509;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Scanner;

/**
 * Қолдану:
 *   java x509.X509Main                                  -> интерактивті режим
 *   java x509.X509Main cert.pem                         -> бір файлды талдау
 *   java x509.X509Main cert.pem --trust root.pem        -> өз түбір сертификатыңды сенімді деп беру
 */
public class X509Main {
    public static void main(String[] args) {
        if (args.length == 0) {
            run(new Scanner(System.in, StandardCharsets.UTF_8));
            return;
        }
        List<Path> files = new ArrayList<>();
        List<Path> trusted = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            if ("--trust".equals(args[i]) && i + 1 < args.length) {
                trusted.add(Paths.get(args[++i]));
            } else {
                files.add(Paths.get(args[i]));
            }
        }
        for (Path f : files) {
            analyze(f, trusted);
        }
    }

    /** Интерактивті режим берілген Scanner-мен (App лаунчері бір Scanner-ді бөліседі). */
    public static void run(Scanner in) {
        System.out.println("X.509 сертификат талдағышы (мысалдар: samples/ папкасында)");
        try {
            while (true) {
                System.out.print("\nСертификат файлының жолы (бос = шығу): ");
                String path = in.nextLine().trim();
                if (path.isEmpty()) {
                    break;
                }
                System.out.print("Сенімді түбір сертификат файлы (бос = жоқ): ");
                String trust = in.nextLine().trim();
                List<Path> trusted = new ArrayList<>();
                if (!trust.isEmpty()) {
                    trusted.add(Paths.get(trust));
                }
                analyze(Paths.get(path), trusted);
            }
        } catch (NoSuchElementException e) {
            // енгізу аяқталды
        }
        System.out.println("X.509 талдағышынан шықтыңыз.");
    }

    static ValidationResult analyze(Path file, List<Path> trustedRoots) {
        CertificateAnalyzer analyzer = new CertificateAnalyzer();
        for (Path root : trustedRoots) {
            try {
                analyzer.addTrustedRoot(root);
            } catch (Exception e) {
                System.out.println("Ескерту: сенімді түбір оқылмады (" + root + "): " + e.getMessage());
            }
        }
        if (!Files.exists(file)) {
            System.out.println("Файл табылмады: " + file.toAbsolutePath());
            return null;
        }
        ValidationResult verdict = analyzer.analyzeCertificate(file);
        analyzer.displayResult();
        return verdict;
    }
}
