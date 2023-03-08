package models.ecies;

import claps.health.ecies.phrECIES;
import claps.health.ecies.phrECIES_Message;
import org.bitcoinj.core.ECKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import claps.health.utils.Utils;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

class phrECIESTest {
    @Test
    public void encrypt() throws Exception {
        ECKey key= phrECIES.getRandomECKey();
        ECKey keyPub= new ECKey(null, key.getPubKey());
        System.out.println("pri= "+ key.getPrivateKeyAsHex());
        System.out.println("pub= "+ key.getPublicKeyAsHex());

        byte[] plain= "Hello world!".getBytes(StandardCharsets.UTF_8);
        phrECIES_Message message = phrECIES.encryptMessage(keyPub, plain);
        byte[] plain_decrypt= phrECIES.decryptMessage(key, message.serialize());
        Assertions.assertArrayEquals(plain, plain_decrypt);
    }

    @Test
    public void encrypt_file() {
        String planTextFileName = "FileInHuge.txt";
        String cipherTextFileName = "FileOutEncrypt.txt";
        String decryptedFileName = "FileOutDecrypt.txt";
        byte[] data= Utils.createDataInBytes(5 * (1024*1024-2), "12345abcde");  //5MB

        FileOutputStream stream = null;
        try {
            stream = new FileOutputStream(planTextFileName);
            stream.write(data);
            stream.close();

            ECKey key= phrECIES.getRandomECKey();
            ECKey keyPub= new ECKey(null, key.getPubKey());
            System.out.println("pri= "+ key.getPrivateKeyAsHex());
            System.out.println("pub= "+ key.getPublicKeyAsHex());

            //encrypt
            FileInputStream enFis = new FileInputStream(planTextFileName);
            FileOutputStream enFos = new FileOutputStream(cipherTextFileName);
            phrECIES.encryptFromFile(keyPub,enFis,enFos);
            enFis.close();
            enFos.close();

            //decrypt
            FileInputStream deFis = new FileInputStream(cipherTextFileName);
            FileOutputStream deFos = new FileOutputStream(decryptedFileName);
            phrECIES.decryptFromFile(key,deFis,deFos);
            deFis.close();
            deFos.close();

            FileInputStream testFis = new FileInputStream(decryptedFileName);
            byte[] plain_text = Utils.get_file_bytes(testFis);
            testFis.close();

            Assertions.assertArrayEquals(data, plain_text);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}