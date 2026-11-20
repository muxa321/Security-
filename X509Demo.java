package x509;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/** samples/ папкасындағы дайын сертификаттармен барлық жағдайды көрсетеді. */
public class X509Demo {
    private static int passed = 0;
    private static int total = 0;

    public static void main(String[] args) {
        if (!Files.isDirectory(Paths.get("samples"))) {
            System.out.println("samples/ папкасы табылмады. Бағдарламаны жоба папкасынан іске қос "
                    + "(VS Code-та папканы File -> Open Folder арқылы аш).");
            return;
        }
        run("1. Дұрыс тізбек (leaf + intermediate + root), түбір сенімді деп берілген",
                "valid-chain.pem", "root-ca.pem", ValidationResult.VALID);
        run("2. Сол тізбек, бірақ түбір сенімді тізімде ЖОҚ",
                "valid-chain.pem", null, ValidationResult.INVALID);
        run("3. Мерзімі өткен сертификат",
                "expired-chain.pem", "root-ca.pem", ValidationResult.INVALID);
        run("4. Қолтаңбасы бұзылған (сертификат өзгертілген)",
                "tampered-chain.pem", "root-ca.pem", ValidationResult.INVALID);
        run("5. Self-signed (өзіне өзі қол қойған) сертификат",
                "self-signed.pem", null, ValidationResult.INVALID);
        run("6. Тек leaf, шығарушысы файлда жоқ, бірақ intermediate сенімді деп берілген",
                "leaf-only.pem", "intermediate-ca.pem", ValidationResult.WARNING);
        run("7. DER форматындағы сертификат (PEM емес)",
                "leaf.der", null, ValidationResult.INVALID);
        run("8. Сертификат емес файл",
                "not-a-certificate.txt", null, ValidationResult.INVALID);

        System.out.println();
        System.out.println("Күтілген нәтиже сәйкес келді: " + passed + " / " + total);
    }

    private static void run(String title, String file, String trustRoot, String expected) {
        System.out.println();
        System.out.println("##### " + title);
        List<Path> trusted = new ArrayList<>();
        if (trustRoot != null) {
            trusted.add(Paths.get("samples", trustRoot));
        }
        ValidationResult verdict = X509Main.analyze(Paths.get("samples", file), trusted);
        total++;
        boolean ok = verdict != null && expected.equals(verdict.getStatus());
        if (ok) {
            passed++;
        }
        System.out.println((ok ? "[OK] " : "[ҚАТЕ] ") + "күтілген: " + expected
                + ", шықты: " + (verdict == null ? "-" : verdict.getStatus()));
    }
}
