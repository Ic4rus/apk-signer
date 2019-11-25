package com.android.apksig.s2s;

import com.android.apksig.ApkSigner;
import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.apk.MinSdkVersionException;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

public class Test {

    public static void main(String[] args) throws Exception {

        File outputApk = new File("app2_signed.apk");
        File inputApk = new File("app2.apk");
        boolean verbose = false;
        boolean v1SigningEnabled = true;
        boolean v2SigningEnabled = true;
        boolean v3SigningEnabled = true;
        boolean debuggableApkPermitted = true;
        int minSdkVersion = 1;
        boolean minSdkVersionSpecified = false;
        int maxSdkVersion = Integer.MAX_VALUE;
        List<SignerParams> signers = new ArrayList<>(1);
        SignerParams signerParams = new SignerParams();
        SigningCertificateLineage lineage = null;
        List<ProviderInstallSpec> providers = new ArrayList<>();
        ProviderInstallSpec providerParams = new ProviderInstallSpec();

        signerParams.setKeystoreFile("demo.jks");
        if (!signerParams.isEmpty()) {
            signers.add(signerParams);
        }
        signerParams = null;
        if (!providerParams.isEmpty()) {
            providers.add(providerParams);
        }
        providerParams = null;

        // Install additional JCA Providers
        for (ProviderInstallSpec providerInstallSpec : providers) {
            providerInstallSpec.installProvider();
        }

        List<ApkSigner.SignerConfig> signerConfigs = new ArrayList<>(signers.size());
        int signerNumber = 0;
        try (PasswordRetriever passwordRetriever = new PasswordRetriever()) {
            for (SignerParams signer : signers) {
                signerNumber++;
                signer.setName("signer #" + signerNumber);
                try {
                    signer.loadPrivateKeyAndCerts(passwordRetriever);
                } catch (ParameterException e) {
                    System.err.println(
                            "Failed to load signer \"" + signer.getName() + "\": "
                                    + e.getMessage());
                    System.exit(2);
                    return;
                } catch (Exception e) {
                    System.err.println("Failed to load signer \"" + signer.getName() + "\"");
                    e.printStackTrace();
                    System.exit(2);
                    return;
                }
                String v1SigBasename;
                if (signer.getV1SigFileBasename() != null) {
                    v1SigBasename = signer.getV1SigFileBasename();
                } else if (signer.getKeystoreKeyAlias() != null) {
                    v1SigBasename = signer.getKeystoreKeyAlias();
                } else if (signer.getKeyFile() != null) {
                    String keyFileName = new File(signer.getKeyFile()).getName();
                    int delimiterIndex = keyFileName.indexOf('.');
                    if (delimiterIndex == -1) {
                        v1SigBasename = keyFileName;
                    } else {
                        v1SigBasename = keyFileName.substring(0, delimiterIndex);
                    }
                } else {
                    throw new RuntimeException(
                            "Neither KeyStore key alias nor private key file available");
                }
                ApkSigner.SignerConfig signerConfig =
                        new ApkSigner.SignerConfig.Builder(
                                v1SigBasename, signer.getPrivateKey(), signer.getCerts())
                                .build();
                signerConfigs.add(signerConfig);
            }
        }

        if (outputApk == null) {
            outputApk = inputApk;
        }
        File tmpOutputApk;
        if (inputApk.getCanonicalPath().equals(outputApk.getCanonicalPath())) {
            tmpOutputApk = File.createTempFile("apksigner", ".apk");
            tmpOutputApk.deleteOnExit();
        } else {
            tmpOutputApk = outputApk;
        }
        ApkSigner.Builder apkSignerBuilder =
                new ApkSigner.Builder(signerConfigs)
                        .setInputApk(inputApk)
                        .setOutputApk(tmpOutputApk)
                        .setOtherSignersSignaturesPreserved(false)
                        .setV1SigningEnabled(v1SigningEnabled)
                        .setV2SigningEnabled(v2SigningEnabled)
                        .setV3SigningEnabled(v3SigningEnabled)
                        .setDebuggableApkPermitted(debuggableApkPermitted)
                        .setSigningCertificateLineage(lineage);
        if (minSdkVersionSpecified) {
            apkSignerBuilder.setMinSdkVersion(minSdkVersion);
        }
        ApkSigner apkSigner = apkSignerBuilder.build();
        try {
            apkSigner.sign();
        } catch (MinSdkVersionException e) {
            String msg = e.getMessage();
            if (!msg.endsWith(".")) {
                msg += '.';
            }
            throw new MinSdkVersionException(
                    "Failed to determine APK's minimum supported platform version"
                            + ". Use --min-sdk-version to override",
                    e);
        }
        if (!tmpOutputApk.getCanonicalPath().equals(outputApk.getCanonicalPath())) {
            Files.move(
                    tmpOutputApk.toPath(), outputApk.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }

        if (verbose) {
            System.out.println("Signed");
        }
    }

    private static class ProviderInstallSpec {
        String className;
        String constructorParam;
        Integer position;

        private boolean isEmpty() {
            return (className == null) && (constructorParam == null) && (position == null);
        }

        private void installProvider() throws Exception {
            if (className == null) {
                throw new ParameterException(
                        "JCA Provider class name (--provider-class) must be specified");
            }

            Class<?> providerClass = Class.forName(className);
            if (!Provider.class.isAssignableFrom(providerClass)) {
                throw new ParameterException(
                        "JCA Provider class " + providerClass + " not subclass of "
                                + Provider.class.getName());
            }
            Provider provider;
            if (constructorParam != null) {
                // Single-arg Provider constructor
                provider =
                        (Provider) providerClass.getConstructor(String.class)
                                .newInstance(constructorParam);
            } else {
                // No-arg Provider constructor
                provider = (Provider) providerClass.getConstructor().newInstance();
            }

            if (position == null) {
                Security.addProvider(provider);
            } else {
                Security.insertProviderAt(provider, position);
            }
        }
    }
}
