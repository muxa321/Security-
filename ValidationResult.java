package x509;

import java.util.List;

/** Бір тексерудің нәтижесі: статус (VALID / WARNING / INVALID) және қате хабарламасы. */
public class ValidationResult {
    public static final String VALID = "VALID";
    public static final String WARNING = "WARNING";
    public static final String INVALID = "INVALID";

    private final String checkName;     // қандай тексеру
    private final String status;
    private final String errorMessage;  // WARNING / INVALID болғанда себебі
    private final String info;          // VALID болғанда егжей-тегжей

    private ValidationResult(String checkName, String status, String errorMessage, String info) {
        this.checkName = checkName;
        this.status = status;
        this.errorMessage = errorMessage;
        this.info = info;
    }

    public static ValidationResult valid(String checkName, String info) {
        return new ValidationResult(checkName, VALID, "", info);
    }

    public static ValidationResult warning(String checkName, String message) {
        return new ValidationResult(checkName, WARNING, message, "");
    }

    public static ValidationResult invalid(String checkName, String message) {
        return new ValidationResult(checkName, INVALID, message, "");
    }

    /** Бірнеше нәтижеден ең нашарын (INVALID > WARNING > VALID) алып, қорытынды жасайды. */
    public static ValidationResult overall(String checkName, List<ValidationResult> results) {
        int invalid = 0;
        int warning = 0;
        for (ValidationResult r : results) {
            if (INVALID.equals(r.status)) {
                invalid++;
            } else if (WARNING.equals(r.status)) {
                warning++;
            }
        }
        if (invalid > 0) {
            return invalid(checkName, "сәтсіз тексеру саны: " + invalid + (warning > 0 ? ", ескерту: " + warning : ""));
        }
        if (warning > 0) {
            return warning(checkName, "ескерту саны: " + warning);
        }
        return valid(checkName, "барлық тексеру өтті (" + results.size() + ")");
    }

    public boolean isValid() {
        return VALID.equals(status);
    }

    public String getCheckName() {
        return checkName;
    }

    public String getStatus() {
        return status;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    /** Нәтиженің бір жолдық сипаттамасы. */
    public String getResult() {
        String text = errorMessage.isEmpty() ? info : errorMessage;
        return String.format("[%-7s] %s: %s", status, checkName, text);
    }

    @Override
    public String toString() {
        return getResult();
    }
}
