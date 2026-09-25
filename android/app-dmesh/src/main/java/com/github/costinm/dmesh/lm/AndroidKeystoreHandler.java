package com.github.costinm.dmesh.lm;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.os.Bundle;

import com.github.costinm.dmesh.MeshStream;
import com.github.costinm.dmesh.MeshStreamHandler;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;

/** Private Android Keystore adapter for Rust. The private key never crosses JNI. */
final class AndroidKeystoreHandler implements MeshStreamHandler {
    private static final String PROVIDER = "AndroidKeyStore";
    private static final String ALIAS = "attestation_key";

    @Override
    public synchronized MeshStream handle(MeshStream request)
            throws GeneralSecurityException, IOException {
        String method = request.method;
        KeyStore store = KeyStore.getInstance(PROVIDER);
        store.load(null);
        if ("ensure".equals(method)) {
            byte[] payload = request.data.getByteArray("challenge");
            if (payload == null || payload.length == 0 || payload.length > 128) {
                throw new IllegalArgumentException("attestation challenge must be 1..128 bytes");
            }
            // The challenge applies when the app-scoped key is first created.
            // Rust can inspect the returned DER chain before trusting it.
            if (!store.containsAlias(ALIAS)) {
                KeyPairGenerator generator = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC, PROVIDER);
                KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                        ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1"))
                        .setUserAuthenticationRequired(false)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setAttestationChallenge(payload.clone())
                        .build();
                generator.initialize(spec);
                generator.generateKeyPair();
            }
            Certificate[] chain = store.getCertificateChain(ALIAS);
            if (chain == null || chain.length == 0) {
                throw new GeneralSecurityException("attestation certificate chain unavailable");
            }
            MeshStream response = new MeshStream("ensure.result");
            Bundle certs = new Bundle();
            for (int i = 0; i < chain.length; i++) {
                certs.putByteArray(String.valueOf(i), chain[i].getEncoded());
            }
            response.data.putBundle("certificates", certs);
            return response;
        }
        if ("sign".equals(method)) {
            byte[] payload = request.data.getByteArray("message");
            if (payload == null) throw new IllegalArgumentException("missing signing payload");
            PrivateKey key = (PrivateKey) store.getKey(ALIAS, null);
            if (key == null) throw new GeneralSecurityException("attestation key unavailable");
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(key);
            signer.update(payload);
            MeshStream response = new MeshStream("sign.result");
            response.data.putByteArray("signature", signer.sign());
            return response;
        }
        throw new IllegalArgumentException("unknown keystore operation");
    }
}
