package com.arcs.security;

import org.apache.commons.lang3.Validate;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PemReader {

    public static PrivateKey readPrivateKey(final String filePath) throws NoSuchProviderException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        Validate.notNull(filePath);
        final KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
        final PrivateKey privateKey = generatePrivateKey(factory, filePath);
        return privateKey;
    }

    public static PublicKey readPublicKey(final String filePath) throws NoSuchProviderException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        Validate.notNull(filePath);
        final KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
        final PublicKey publicKey = generatePublicKey(factory, filePath);
        return publicKey;
    }

    private static PrivateKey generatePrivateKey(final KeyFactory factory, final String filename) throws InvalidKeySpecException, IOException {
        Validate.notNull(factory);
        Validate.notNull(filename);
        final PemFileReader pemFileReader = new PemFileReader(filename);
        final byte[] content = pemFileReader.getPemObject().getContent();
        final PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
        return factory.generatePrivate(privKeySpec);
    }

    private static PublicKey generatePublicKey(final KeyFactory factory, final String filename) throws InvalidKeySpecException, IOException {
        Validate.notNull(factory);
        Validate.notNull(filename);
        final PemFileReader pemFileReader = new PemFileReader(filename);
        final byte[] content = pemFileReader.getPemObject().getContent();
        final X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
        return factory.generatePublic(pubKeySpec);
    }

}
