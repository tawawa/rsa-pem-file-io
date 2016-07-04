package com.arcs.security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import static com.arcs.security.PemReader.readPrivateKey;
import static com.arcs.security.PemReader.readPublicKey;
import static com.arcs.security.PemWriter.writePrivateKey;
import static com.arcs.security.PemWriter.writePublicKey;

public class Main {

    public static final int KEY_SIZE = 2048;

    public final static String RESOURCES_DIR = "src/main/resources/";
    public final static String PRIVATE_KEY_PEM_FILENAME = "id_rsa";
    public final static String PUBLIC_KEY_PEM_FILENAME = "id_rsa.pub";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        writePems();
        readPems();
    }

    private static void writePems() throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        // create key pair
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(KEY_SIZE);
        final KeyPair keyPair = generator.generateKeyPair();

        // write private key
        final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        writePrivateKey(privateKey, "RSA PRIVATE KEY", RESOURCES_DIR + PRIVATE_KEY_PEM_FILENAME);
        // write public key
        final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        writePublicKey(publicKey, "RSA PUBLIC KEY", RESOURCES_DIR + PUBLIC_KEY_PEM_FILENAME);
    }

    private static void readPems() throws NoSuchProviderException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        // read pem files
        final PrivateKey privateKey = readPrivateKey(RESOURCES_DIR + PRIVATE_KEY_PEM_FILENAME);
        System.out.println("privateKey = " + privateKey.toString());

        final PublicKey publicKey = readPublicKey(RESOURCES_DIR + PUBLIC_KEY_PEM_FILENAME);
        System.out.println("publicKey = " + publicKey.toString());
    }

}
