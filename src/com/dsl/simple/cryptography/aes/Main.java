package com.dsl.simple.cryptography.aes;

import com.dsl.simple.cryptography.aes.utils.CryptoAES;

import java.util.Objects;

public class Main
{
    public static void main(String[] args)
    {
        String text = "This is confidential text";
        System.out.println("Before Encrypt: " + text);
        String encryptedString = CryptoAES.encrypt(text);
        if(Objects.nonNull(encryptedString))
        {
            System.out.println("After Encrypted: " + encryptedString);
            String decryptedString = CryptoAES.decrypt(encryptedString);
            System.out.println("After Decrypted: " + decryptedString);
        }

    }
}
