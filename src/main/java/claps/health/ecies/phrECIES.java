/*
 * Copyright (c) <2023> <DTCO>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package claps.health.ecies;

import org.bitcoinj.core.ECKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import claps.health.utils.EncryptAES;
import claps.health.utils.Hash;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.channels.FileChannel;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;

public class phrECIES {
    private static final Provider BC = new org.bouncycastle.jce.provider.BouncyCastleProvider();

    private static AlgorithmParameters parameters;
    private static ECParameterSpec ecParameters;
    private static KeyFactory kf;
    private static int maxCipherLengthForMac = 1024 * 1024; //1MB

    static {
        try {
            parameters= AlgorithmParameters.getInstance("EC", BC);
            parameters.init(new ECGenParameterSpec("secp256k1"));
            ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
            kf = KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
        } catch (InvalidParameterSpecException e) {
//            e.printStackTrace();
        }
    }

    public static byte[] getRandomData(int size){
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[size];
        random.nextBytes(bytes);
        return bytes;
    }

    public static ECKey getRandomECKey(){
        ECKey ecKey = new ECKey(getRandomData(phrECIES_Message.EPHEM_PRV_KEY_LEN), null);
        return ecKey;
    }

    public static void setToCipherPosition(FileChannel fileChannel, int position) throws IOException {
        fileChannel.position(position);
    }

    public static byte[] ecdsa256Sign(byte[] prvkeyBytes, byte[]  dataBytes) throws NoSuchAlgorithmException, phrECIES_Exception, SignatureException, InvalidKeySpecException, InvalidKeyException {
        if(prvkeyBytes.length != 32) throw new phrECIES_Exception("privkey length error");
        KeyFactory kf = KeyFactory.getInstance("EC");
        ECPrivateKeySpec specPrivate = new ECPrivateKeySpec(new BigInteger(prvkeyBytes), ecParameters);
        PrivateKey priKey = kf.generatePrivate(specPrivate);

        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(priKey);
        signature.update(dataBytes);
        byte[] res = signature.sign();
        return res;
    }
    public static boolean ecdsa256Verify(byte[] pubkeyBytes, byte[]  dataBytes, byte[] signValue) throws NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, InvalidKeyException {
        //for android
        byte[] pub = pubkeyBytes;
        ECPoint ep;
        if(pub.length== phrECIES_Message.EMPUB_LEN) ep= new ECPoint(new BigInteger(1, Arrays.copyOfRange(pub, 1, 33)), new BigInteger(1, Arrays.copyOfRange(pub, 33, phrECIES_Message.EMPUB_LEN)));
        else ep= new ECPoint(new BigInteger(1, Arrays.copyOfRange(pub, 0, 32)), new BigInteger(1, Arrays.copyOfRange(pub, 32, 64)));

        KeyFactory kf = KeyFactory.getInstance("EC");
        ECPublicKeySpec specPublic= new ECPublicKeySpec(ep, ecParameters);
        PublicKey publicKey = kf.generatePublic(specPublic);

        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(publicKey);
        signature.update(dataBytes);
        boolean result = signature.verify(signValue);
        return result;
    }

    //uncompressed
    private static byte[] encodeECPublicKey(BCECPublicKey pubKey) {
        int len= pubKey.getEncoded().length;
        return Arrays.copyOfRange(pubKey.getEncoded(), 23, len);
    }

    private static byte[] getMac(byte[] macKey, byte[] iv, byte[] pubkey_ephemeral, byte[] cipher_text, int maxCipherLengthForMac) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(iv);
        os.write(pubkey_ephemeral);
        if(cipher_text.length > maxCipherLengthForMac){
            os.write(Arrays.copyOfRange(cipher_text,0, maxCipherLengthForMac));
        }else{
            os.write(cipher_text);
        }
        return Hash.hmacSha256(macKey, os.toByteArray());
    }

    public static JCEECPublicKey loadPublicKey(byte[] pub) throws InvalidKeySpecException {
        ECPoint ep;
        if(pub.length== phrECIES_Message.EMPUB_LEN) ep= new ECPoint(new BigInteger(1, Arrays.copyOfRange(pub, 1, 33)), new BigInteger(1, Arrays.copyOfRange(pub, 33, phrECIES_Message.EMPUB_LEN)));
        else ep= new ECPoint(new BigInteger(1, Arrays.copyOfRange(pub, 0, 32)), new BigInteger(1, Arrays.copyOfRange(pub, 32, 64)));

        ECPublicKeySpec specPublic= new ECPublicKeySpec(ep, ecParameters);
        ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(specPublic);
        return new JCEECPublicKey(publicKey);
    }

    public static JCEECPrivateKey loadPrivateKey(byte[] priv) throws InvalidKeySpecException {
        ECPrivateKeySpec specPrivate = new ECPrivateKeySpec(new BigInteger(priv), ecParameters);
        ECPrivateKey privateKey = (ECPrivateKey) kf.generatePrivate(specPrivate);
        return new JCEECPrivateKey(privateKey);
    }

    public static JCEECPrivateKey loadPrivateKey(ECKey priv) throws InvalidKeySpecException {
        ECPrivateKeySpec specPrivate = new ECPrivateKeySpec(priv.getPrivKey(), ecParameters);
        ECPrivateKey privateKey = (ECPrivateKey) kf.generatePrivate(specPrivate);
        return new JCEECPrivateKey(privateKey);
    }

    //derive from encryptMessage
    public static ECKey getPrivkeyEphemeral(byte[] privkey1_ephemeral) throws Exception {
        if(privkey1_ephemeral.length != 32) throw new phrECIES_Exception("privkey length error");
        return new ECKey(privkey1_ephemeral, null);
    }
    //derive from encryptMessage
    public static ECKey getPublickeyEphemeral(byte[] pubkey2) throws Exception {
        if(pubkey2.length == (phrECIES_Message.EMPUB_LEN-1)) {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            os.write(0x04);
            os.write(pubkey2);
            pubkey2= os.toByteArray();
        }

        if(pubkey2.length != phrECIES_Message.EMPUB_LEN) throw new phrECIES_Exception("pubkey key length error");
        return new ECKey(null, pubkey2);
    }
    public static phrECIES_Message encryptMessage(byte[] privkey1_ephemeral, byte[] pubkey2, byte[] message) throws Exception {
        return encryptMessage(getPrivkeyEphemeral(privkey1_ephemeral), getPublickeyEphemeral(pubkey2), message);
    }

    public static phrECIES_Message encryptMessage(ECKey privkey_ephemeral, ECKey pubkey, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, IOException, phrECIES_Exception, InvalidKeySpecException {
        byte[] iv = getRandomData(phrECIES_Message.IV_LEN);

        JCEECPrivateKey ec_privkey_ephemeral = (JCEECPrivateKey) loadPrivateKey(privkey_ephemeral);
        JCEECPublicKey ec_pubkey= (JCEECPublicKey) loadPublicKey(pubkey.getPubKey());
        byte[] pubkey_ephemeral = privkey_ephemeral.getPubKey();

        KeyAgreement KeyAgree = KeyAgreement.getInstance("ECDH", BC);
        KeyAgree.init(ec_privkey_ephemeral);
        KeyAgree.doPhase(ec_pubkey, true);

        byte[] shareSecret = KeyAgree.generateSecret();
        byte[] encryptionKeyHash512= Hash.sha512(shareSecret);
        byte[] shareSecretHsah= Arrays.copyOfRange(encryptionKeyHash512, 0, 32);
        byte[] macKey= Arrays.copyOfRange(encryptionKeyHash512, 32, 64);
        byte[] cipher_text= EncryptAES.aes_encrypt(iv, shareSecretHsah, message);
        byte[] mac= getMac(macKey, iv, pubkey_ephemeral, cipher_text,maxCipherLengthForMac);

        return new phrECIES_Message(iv, mac, pubkey_ephemeral, cipher_text);
    }
    //from file, byte
    public static void encryptFromFile(byte[] privkey1_ephemeral,byte[]pubkey2,FileInputStream fileInputStream, FileOutputStream fileOutputStream) throws Exception {
        encryptFromFile(getPrivkeyEphemeral(privkey1_ephemeral), getPublickeyEphemeral(pubkey2),fileInputStream,fileOutputStream);
    }
    //random private key, from file, byte
    public static void encryptFromFile(byte[]pubkey2,FileInputStream fileInputStream, FileOutputStream fileOutputStream) throws Exception {
        encryptFromFile(getPrivkeyEphemeral(pubkey2),fileInputStream,fileOutputStream);
    }
    //random private key
    public static phrECIES_Message encryptMessage(ECKey pubkey, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, IOException, phrECIES_Exception, InvalidKeySpecException {
        ECKey privkey_ephemeral= getRandomECKey();
        return encryptMessage(privkey_ephemeral,pubkey,message);
    }

    //random private key, from file
    public static void encryptFromFile(ECKey pubkey,FileInputStream fileInputStream, FileOutputStream fileOutputStream) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {
        ECKey privkey_ephemeral= getRandomECKey();
        encryptFromFile(privkey_ephemeral,pubkey,fileInputStream,fileOutputStream);
    }
    //from file
    public static void encryptFromFile(ECKey privkey_ephemeral, ECKey pubkey,FileInputStream fileInputStream, FileOutputStream fileOutputStream) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {
//        byte[] iv = new byte[phrECIES_Message.IV_LEN];
//        new Random().nextBytes(iv);
        byte[] iv = getRandomData(phrECIES_Message.IV_LEN);

        JCEECPrivateKey ec_privkey_ephemeral = loadPrivateKey(privkey_ephemeral);
        JCEECPublicKey ec_pubkey = loadPublicKey(pubkey.getPubKey());
        byte[] pubkey_ephemeral = privkey_ephemeral.getPubKey();

        KeyAgreement KeyAgree = KeyAgreement.getInstance("ECDH", BC);
        KeyAgree.init(ec_privkey_ephemeral);
        KeyAgree.doPhase(ec_pubkey, true);

        byte[] shareSecret = KeyAgree.generateSecret();
        byte[] encryptionKeyHash512= Hash.sha512(shareSecret);
        byte[] shareSecretHsah= Arrays.copyOfRange(encryptionKeyHash512, 0, 32);
        byte[] macKey= Arrays.copyOfRange(encryptionKeyHash512, 32, 64);
        setToCipherPosition(fileOutputStream.getChannel(), phrECIES_Message.HEADER_SIZE);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream = EncryptAES.aes_encrypt_file(iv, shareSecretHsah, fileInputStream, fileOutputStream, maxCipherLengthForMac,byteArrayOutputStream);
        byte[] mac= getMac(macKey, iv, pubkey_ephemeral, byteArrayOutputStream.toByteArray(),maxCipherLengthForMac);
        byteArrayOutputStream.close();
        phrECIES_Message.serializeToFile(fileOutputStream,iv,mac,pubkey_ephemeral);
    }

    public static byte[] decryptMessage(byte[] privkey, byte[] serialize) throws Exception {
        return decryptMessage(getPrivkeyEphemeral(privkey), serialize);
    }
    public static void decryptFromFile(byte[] privkey,FileInputStream fileInputStream, FileOutputStream fileOutputStream) throws Exception {
        decryptFromFile(getPrivkeyEphemeral(privkey), fileInputStream,fileOutputStream);
    }
    public static void decryptFromFile(ECKey privkey,FileInputStream fileInputStream, FileOutputStream fileOutputStream) throws Exception {
        phrECIES_Message pmsg_deser = phrECIES_Message.deserialize(fileInputStream,maxCipherLengthForMac);

        if(pmsg_deser==null) throw new phrECIES_Exception("ECIES message is null");
        if(pmsg_deser.getPubkeyEphemeral().length != phrECIES_Message.EMPUB_LEN) throw new phrECIES_Exception("pubkey ephemeral length error");

        JCEECPrivateKey ec_privkey = loadPrivateKey(privkey);
        JCEECPublicKey ec_pubkey_ephemeral = loadPublicKey(pmsg_deser.getPubkeyEphemeral());

        KeyAgreement KeyAgree = KeyAgreement.getInstance("ECDH", BC);
        KeyAgree.init(ec_privkey);
        KeyAgree.doPhase(ec_pubkey_ephemeral, true);

        byte[] shareSecret = KeyAgree.generateSecret();
        byte[] encryptionKeyHash512= Hash.sha512(shareSecret);
        byte[] shareSecretHsah= Arrays.copyOfRange(encryptionKeyHash512, 0, 32);
        byte[] macKey= Arrays.copyOfRange(encryptionKeyHash512, 32, 64);
        byte[] mac= getMac(macKey, pmsg_deser.getIV(), pmsg_deser.getPubkeyEphemeral(), pmsg_deser.getCipherText(),maxCipherLengthForMac);

        if(!Arrays.equals(mac, pmsg_deser.getMac())) throw new phrECIES_Exception("mac not compare");

        setToCipherPosition(fileInputStream.getChannel(), phrECIES_Message.HEADER_SIZE);
        EncryptAES.aes_decrypt_file(pmsg_deser.getIV(), shareSecretHsah,fileInputStream,fileOutputStream);
    }

    public static byte[] decryptMessage(ECKey privkey, byte[] serialize) throws Exception {
        phrECIES_Message pmsg_deser= phrECIES_Message.deserialize(serialize);

        if(pmsg_deser.getPubkeyEphemeral().length != phrECIES_Message.EMPUB_LEN) throw new phrECIES_Exception("pubkey ephemeral length error");

        JCEECPrivateKey ec_privkey = (JCEECPrivateKey) loadPrivateKey(privkey);
        JCEECPublicKey ec_pubkey_ephemeral= (JCEECPublicKey) loadPublicKey(pmsg_deser.getPubkeyEphemeral());

        KeyAgreement KeyAgree = KeyAgreement.getInstance("ECDH", BC);
        KeyAgree.init(ec_privkey);
        KeyAgree.doPhase(ec_pubkey_ephemeral, true);

        byte[] shareSecret = KeyAgree.generateSecret();
        byte[] encryptionKeyHash512= Hash.sha512(shareSecret);
        byte[] shareSecretHsah= Arrays.copyOfRange(encryptionKeyHash512, 0, 32);
        byte[] macKey= Arrays.copyOfRange(encryptionKeyHash512, 32, 64);
        byte[] mac= getMac(macKey, pmsg_deser.getIV(), pmsg_deser.getPubkeyEphemeral(), pmsg_deser.getCipherText(),maxCipherLengthForMac);
        if(!Arrays.equals(mac, pmsg_deser.getMac())) throw new phrECIES_Exception("mac not compare");

        byte[] plain_text= EncryptAES.aes_decrypt(pmsg_deser.getIV(), shareSecretHsah, pmsg_deser.getCipherText());
        return plain_text;
    }

}
