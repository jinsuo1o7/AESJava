package org.example;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class AESExampleTest {

    @Test
    void givenString_whenEncrypt_thenSuccess()
            throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {

        String input = "drminside";
        SecretKey key = AESExample.generateKey(128);
        IvParameterSpec ivParameterSpec = AESExample.generateIv();
        String algorithm = "AES/CBC/PKCS5Padding";
        String cipherText = AESExample.encrypt(algorithm, input, key, ivParameterSpec);
        String plainText = AESExample.decrypt(algorithm, cipherText, key, ivParameterSpec);
        Assertions.assertEquals(input, plainText);
    }
}