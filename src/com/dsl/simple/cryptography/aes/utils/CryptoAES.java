package com.dsl.simple.cryptography.aes.utils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoAES
{
    private CryptoAES() {}

    private static final String ALGORITHM = "AES";
    private static byte[] iv;
    private static byte[] secretKey;


    public static String encrypt(String text)
    {
        try
        {
            iv = SecureRandom.getSeed(16);
            secretKey = SecureRandom.getSeed(16);

            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, ALGORITHM);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] encrypted = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e)
        {
            e.printStackTrace();
        }

        return null;
    }

    public static String decrypt(String encryptedString)
    {
        try
        {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, ALGORITHM);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] decodedEncryptedString = Base64.getDecoder().decode(encryptedString.getBytes(StandardCharsets.UTF_8));
            byte[] decrypted = cipher.doFinal(decodedEncryptedString);
            return new String(decrypted, StandardCharsets.UTF_8);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e)
        {
            e.printStackTrace();
        }

        return null;
    }
}
