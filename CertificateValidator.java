package x509;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/** Сертификаттың жарамдылық мерзімін тексереді. */
public class CertificateValidator {
    /** Мерзімі аяқталуына осыдан аз күн қалса — ескерту. */
    public static final int WARN_DAYS = 30;

    private final Clock clock;

    public CertificateValidator() {
        this(Clock.systemUTC());
    }

    public CertificateValidator(Clock clock) {
        this.clock = clock;
    }

    /** Қазіргі уақыт validFrom мен validTo аралығында ма? */
    public ValidationResult checkValidity(X509Certificate cert) {
        String name = "Жарамдылық мерзімі";
        Instant now = clock.instant();
        if (now.isBefore(cert.validFrom)) {
            return ValidationResult.invalid(name,
                    "сертификат әлі күшіне енбеген (validFrom: " + X509Certificate.format(cert.validFrom) + ")");
        }
        if (now.isAfter(cert.validTo)) {
            return ValidationResult.invalid(name,
                    "сертификаттың мерзімі өткен (validTo: " + X509Certificate.format(cert.validTo) + ")");
        }
        return ValidationResult.valid(name, "қазір жарамды");
    }

    /** Мерзімі аяқталуына қанша күн қалғанын тексереді. */
    public ValidationResult checkExpiration(X509Certificate cert) {
        String name = "Мерзімнің аяқталуы";
        Instant now = clock.instant();
        if (now.isAfter(cert.validTo)) {
            long ago = Duration.between(cert.validTo, now).toDays();
            return ValidationResult.invalid(name, "мерзімі " + ago + " күн бұрын аяқталған");
        }
        long left = Duration.between(now, cert.validTo).toDays();
        if (left < WARN_DAYS) {
            return ValidationResult.warning(name, "мерзімі жақында аяқталады: " + left + " күн қалды");
        }
        return ValidationResult.valid(name, "аяқталуына " + left + " күн қалды");
    }
}
