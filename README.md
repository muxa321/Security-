# Курстық жоба: X.509 сертификат талдағышы (Java)

Сыртқы кітапхана керек емес, тек JDK 17+.

```
src/x509/    барлық кластар
samples/     дайын тест сертификаттары (жоба түбірінде болуы керек)
```

## VS Code-та іске қосу
1. JDK 17+ және **Extension Pack for Java** орнат.
2. `File -> Open Folder` арқылы осы `X509Analyzer` папкасын аш (`samples/` жоба түбірінде болсын).
3. Ctrl+Shift+D панелінен "X.509: демо" немесе "X.509: интерактив" таңдап ▶ бас.

## Терминалмен
```
javac -encoding UTF-8 -d out src/x509/*.java
java -Dfile.encoding=UTF-8 -Dstdout.encoding=UTF-8 -cp out x509.X509Demo
java -Dfile.encoding=UTF-8 -Dstdout.encoding=UTF-8 -cp out x509.X509Main samples/valid-chain.pem --trust samples/root-ca.pem
```
Windows-та қазақ әріптері "???" болып шықса: `chcp 65001` жазып қайта іске қос.

## Құрылым
Кластар: `CertificateAnalyzer`, `CertificateParser`, `CertificateValidator`, `SignatureVerifier`,
`ChainValidator`, `X509Certificate`, `ValidationResult`.
- Тексереді: файл форматы (PEM/DER), мерзім, қалған күн, цифрлық қолтаңба, тізбек (PKIX).
- Статус: `VALID`, `WARNING`, `INVALID`.
- Шектеулер: CRL/OCSP өшірілген, домен аты тексерілмейді. `samples/` сертификаттары оқу мысалы (`keytool`-мен жасалған).
