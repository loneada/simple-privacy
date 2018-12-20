package com.benjamin.simpleprivacy;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * The PrivacyUtil class provids a collection of static methods to encryption/decryption file and generate/verify message digests.
 * The encrypt and decrypt methods provide encryption/decryption functionalities using AES/CBC or AES/ECB cipher (128bits).
 * The generateDigest and verifyDigest methods provide message digest functionality of MD5, SHA1, SHA224, SHA256, SHA384 and SHA512.
 */
public class PrivacyUtil {
    private static final String CBC_MAGIC = "BCBC";
    private static final String ECB_MAGIC = "BECB";
    private static final int MAGIC_LEN = 4;
    private static final int SALT_LEN = 16;

    /**
     * Cipher algorithms used to encryt/decrypt data.
     * Every implementation of java platform is required to support AES128/CBC and AES128/ECB.
     */
    public static enum CryptMode {AES128_CBC, AES128_ECB}

    /**
     * Hash algorithms used to generate/verify message digests.
     * Every implementation of java platform is required to support MD5, SHA1 and SHA256.
     * But other algorithms may not be usable on all platforms (although the oracle implementation does support them).
     * 
     */
    public static enum DigestMode {MD5, SHA1, SHA224, SHA256, SHA384, SHA512}

    /**
     * Pad data to meet the block size requirement of encryption algorithms.
     * The value used to fill padded bytes is the count of padding bytes (i.e. blockSize - dataSize).
     * @param data The last chunk of data to encryption (may be zero byte).
     * @param blockSize The block size of specific algorithm (in bytes not bits).
     * @return A block of data with padding added.
     */
    public static byte[] pad(byte[] data, int blockSize) {
        byte[] block = new byte[blockSize];
        for (int i = 0; i < data.length; ++i) {block[i] = data[i];}
        int padding = blockSize - data.length;
        for (int i = data.length; i < blockSize; ++i) {block[i] = (byte) padding;}
        return block;
    }

    /**
     * Strip paddings from decrypted block.
     * @param block The last decrypted block to strip paddings.
     * @return The original data without padding (may be zero byte).
     */
    public static byte[] unpad(byte[] block) {
        int blockSize = block.length;
        int dataSize = blockSize - block[blockSize - 1];
        byte[] data = new byte[dataSize];
        for (int i = 0; i < dataSize; ++i) {data[i] = block[i];}
        return data;
    }

    /**
     * Convert an array of bytes into a hexadecimal string.
     * @param data The array of bytes contains binary data.
     * @return The hexadecimal string representation.
     */
    public static String toHexString(byte[] data) {
        StringBuilder builder = new StringBuilder();
        for (byte b: data) {builder.append(String.format("%02x", Byte.toUnsignedInt(b)));}
        return builder.toString();
    }

    /**
     * Compute message digests using specific hash algorithm.
     * @param mode The hash algorithm used to generate the digest.
     * @param in An InputStream object opened for the message file to calculate the digest.
     *           This mehtod does not close the InputStream object, it is the caller's duty to close it.
     * @return An array of bytes for the resulting hash value.
     * @throws NoSuchAlgorithmException If current java platform doesn't support a specific hash algorithm.
     * @throws IOException If any I/O error occurs when reading from the InputStream object.
     * @throws InterruptedException If current thread is interrupted.
     * @see java.io.InputStream
     */
    public static byte[] generateDigest(DigestMode mode, InputStream in) throws NoSuchAlgorithmException, IOException, InterruptedException {
        String algorithm = "";
        switch(mode) {
            case MD5: algorithm = "MD5"; break;
            case SHA1: algorithm = "SHA-1"; break;
            case SHA224: algorithm = "SHA-224"; break;
            case SHA256: algorithm = "SHA-256"; break;
            case SHA384: algorithm = "SHA-384"; break;
            case SHA512: algorithm = "SHA-512"; break;
            default: break;
        }
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] buf = new byte[512];
        int bytesRead = -1;
        while ((bytesRead = in.read(buf)) != -1) {
            if (Thread.interrupted()) {throw new InterruptedException();}
            md.update(buf, 0, bytesRead);
        }
        return md.digest();
    }

    /**
     * Verify the digest value of a specific file.
     * @param mode The hash algorithm used to generate the message digest.
     * @param file The file of which digest value is verified.
     * @param digest The digest value to be verified.
     * @return A boolean value indicates whether the message digest matches.
     * @throws NoSuchAlgorithmException If current java platform doesn't support a specific hash algorithm.
     * @throws IOException If any I/O error occurs.
     * @throws InterruptedException If current thread is interrupted.
     */
    public static boolean verifyDigest(DigestMode mode, Path file, String digest) throws NoSuchAlgorithmException, IOException, InterruptedException {
        try(InputStream in = Files.newInputStream(file); BufferedInputStream buffered = new BufferedInputStream(in)) {
            return toHexString(generateDigest(mode, buffered)).equalsIgnoreCase(digest);
        }
    }

    /**
     * Encrypt a file with the specific password and encryption algorithm.
     * @param mode The encryption algorithm used.
     * @param password The password phrase.
     * @param plainfile The path of the plain file to encrypt.
     * @param cryptfile The path of the crypted output file.
     * @throws GeneralSecurityException If current java platform doesn't support a specific algorithm.
     * @throws IOException If any I/O error occurs.
     * @throws InterruptedException If current thread is interrupted.
     */
    public static void encrypt(CryptMode mode, char[] password, Path plainfile, Path cryptfile) throws GeneralSecurityException, IOException, InterruptedException {
        String algorithm = "";
        switch(mode) {
            case AES128_CBC: algorithm = "AES/CBC/NoPadding"; break;
            case AES128_ECB: algorithm = "AES/ECB/NoPadding"; break;
            default: break;
        }
        Cipher cipher = Cipher.getInstance(algorithm);
        int blockSize = cipher.getBlockSize();
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[SALT_LEN];
        sr.nextBytes(salt);
        SecretKeySpec keySpec = getKeySpec(blockSize, salt, password);
        try(InputStream in = Files.newInputStream(plainfile);
            OutputStream out = Files.newOutputStream(cryptfile);
            BufferedInputStream bufferedIn = new BufferedInputStream(in);
            BufferedOutputStream bufferedOut = new BufferedOutputStream(out)) {
            switch(mode) {
            case AES128_CBC: {
                byte[] iv = new byte[blockSize];
                sr.nextBytes(iv);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
                bufferedOut.write(CBC_MAGIC.getBytes(StandardCharsets.US_ASCII));
                bufferedOut.write(iv);
                break;
            }
            case AES128_ECB:
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
                bufferedOut.write(ECB_MAGIC.getBytes(StandardCharsets.US_ASCII));
                break;
            default:
                break;
            }
            bufferedOut.write(salt);
            while (true) {
                if (Thread.interrupted()) {throw new InterruptedException();}
                byte[] data = getBlockData(blockSize, bufferedIn);
                if (data.length == blockSize) {
                    byte[] crypted = cipher.update(data);
                    if (crypted != null) {bufferedOut.write(crypted);}
                } else {
                    byte[] padded = pad(data, blockSize);
                    byte[] crypted = cipher.doFinal(padded);
                    if (crypted != null) {bufferedOut.write(crypted);}
                    break;
                }
            }
        }
    }

    /**
     * Decrypt a file with the specific password and encryption algorithm.
     * @param mode The encryption algorithm used.
     * @param password The password phrase.
     * @param cryptfile The path of the crypted file to decrypt.
     * @param plainfile The path of output plain file.
     * @throws GeneralSecurityException If current java platform doesn't support a specific algorithm or the crypted file is not intact.
     * @throws IOException If any I/O error occurs, especially the crypted file format is invalid (i.e. it is probably not produced with the corresponding encrypt method).
     * @throws InterruptedException If current thread is interrupted.
     */
    public static void decrypt(CryptMode mode, char[] password, Path cryptfile, Path plainfile) throws GeneralSecurityException, IOException, InterruptedException {
        String algorithm = "";
        switch(mode) {
            case AES128_CBC: algorithm = "AES/CBC/NoPadding"; break;
            case AES128_ECB: algorithm = "AES/ECB/NoPadding"; break;
            default: break;
        }
        Cipher cipher = Cipher.getInstance(algorithm);
        int blockSize = cipher.getBlockSize();
        try(InputStream in = Files.newInputStream(cryptfile);
            OutputStream out = Files.newOutputStream(plainfile);
            BufferedInputStream bufferedIn = new BufferedInputStream(in);
            BufferedOutputStream bufferedOut = new BufferedOutputStream(out)) {
            byte[] magic = getBlockData(MAGIC_LEN, bufferedIn);
            if (magic.length < MAGIC_LEN) throw new IOException("Invalid file format!");
            byte[] iv = null;
            if (mode == CryptMode.AES128_CBC) {
                iv = getBlockData(blockSize, bufferedIn);
                if (iv.length < blockSize) throw new IOException("Invalid file format!");
            }
            byte[] salt = getBlockData(SALT_LEN, bufferedIn);
            if (salt.length < SALT_LEN) throw new IOException("Invalid file format!");
            SecretKeySpec keySpec = getKeySpec(blockSize, salt, password);
            switch(mode) {
            case AES128_CBC:
                if (!CBC_MAGIC.equals(new String(magic, StandardCharsets.US_ASCII))) throw new IOException("Invalid magic number!");
                cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
                break;
            case AES128_ECB:
                if (!ECB_MAGIC.equals(new String(magic, StandardCharsets.US_ASCII))) throw new IOException("Invalid magic number!");
                cipher.init(Cipher.DECRYPT_MODE, keySpec);
                break;
            default:
                break;
            }
            byte[] lastBlock = null;
            while (true) {
                if (Thread.interrupted()) {throw new InterruptedException();}
                byte[] block = getBlockData(blockSize, bufferedIn);
                if (block.length != 0) {
                    if (block.length < blockSize) throw new IOException("Invalid file format!");
                    byte[] data = cipher.update(block);
                    if (data != null) {
                        if (lastBlock != null) {bufferedOut.write(lastBlock);}
                        lastBlock = data;
                    }
                } else {
                    byte[] data = cipher.doFinal();
                    if (data != null && data.length > 0) {
                        if (lastBlock != null) {bufferedOut.write(lastBlock);}
                        lastBlock = data;
                    }
                    if (lastBlock.length > blockSize) {
                        bufferedOut.write(lastBlock, 0, lastBlock.length - blockSize);
                        lastBlock = Arrays.copyOfRange(lastBlock, lastBlock.length - blockSize, lastBlock.length);
                    }
                    byte[] unpadded = unpad(lastBlock);
                    if (unpadded.length > 0) {bufferedOut.write(unpadded);}
                    break;
                }
            }
        }
    }

    /**
     * Construct a SecretKeySpec object from the password phrase and salt bits.
     * @param keySize The key size (in bytes not bits).
     * @param salt The random salt bytes.
     * @param password The password phrase.
     * @return A SecretKeySpec object for specific algorithm.
     * @throws NoSuchAlgorithmException If current java platform doesn't support a specific algorithm.
     * @throws IOException If any I/O error occurs.
     * @throws InterruptedException If current thread is interrupted.
     */
    private static SecretKeySpec getKeySpec(int keySize, byte[] salt, char[] password) throws NoSuchAlgorithmException, IOException, InterruptedException {
        byte[] saltedPassword = new byte[password.length + SALT_LEN];
        for (int i = 0; i < password.length; ++i) {
            saltedPassword[i] = (byte) password[i];
            password[i] = '0';
        }
        for (int i = password.length, j = 0; i < saltedPassword.length; ++i, ++j) {saltedPassword[i] = salt[j];}
        SecureRandom sr = new SecureRandom(generateDigest(DigestMode.SHA256, new ByteArrayInputStream(saltedPassword)));
        Arrays.fill(saltedPassword, (byte) 0);
        byte[] key = new byte[keySize];
        sr.nextBytes(key);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Arrays.fill(key, (byte) 0);
        return keySpec;
    }

    /**
     * Get a data block of specific size from the InputStream.
     * @param blockSize The block size.
     * @param in The InputStream object to read data.
     * @return A data block of specific size (may be less than blockSize if it is the last block of input).
     * @throws IOException If any I/O error occurs.
     */
    private static byte[] getBlockData(int blockSize, InputStream in) throws IOException {
        byte[] block = new byte[blockSize];
        int len = 0;
        while (len < blockSize) {
            int b = in.read();
            if (b == -1) break;
            block[len] = (byte) b;
            ++len;
        }
        return len < blockSize ? Arrays.copyOf(block, len) : block;
    }
}
