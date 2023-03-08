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

import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class phrECIES_Message {

    public final static int EPHEM_PRV_KEY_LEN = 64;
    public final static int IV_LEN = 16;
    public final static int MAC_LEN = 32;
    public final static int EMPUB_LEN = 65;
    public static final int HEADER_SIZE = IV_LEN + MAC_LEN + EMPUB_LEN;
    public static final int START_POSITION = 0;
    public final static int CIPHER_BLOCK = 16;  //AES
    private byte[] iv;
    private byte[] mac;
    private byte[] pubkey_ephemeral;
    private byte[] cipher_text;

    public phrECIES_Message(byte[] iv, byte[] mac, byte[] pubkey_ephemeral, byte[] cipher_text) throws phrECIES_Exception {
        if(iv.length != IV_LEN) throw new phrECIES_Exception("iv length error");
        if(mac.length != MAC_LEN) throw new phrECIES_Exception("mac length error");
        if(pubkey_ephemeral.length != EMPUB_LEN) throw new phrECIES_Exception("pubkey_ephemeral length error");
        if((cipher_text.length % CIPHER_BLOCK) != 0) throw new phrECIES_Exception("cipher_text length error");

        this.iv= iv;
        this.mac= mac;
        this.pubkey_ephemeral= pubkey_ephemeral;
        this.cipher_text= cipher_text;
    }

    public static void serializeToFile(FileOutputStream fileOutputStream, byte[] iv, byte[]mac, byte[] pubKey) throws IOException {
        phrECIES.setToCipherPosition(fileOutputStream.getChannel(), START_POSITION);
        fileOutputStream.write(iv,0,iv.length);
        fileOutputStream.write(mac,0,mac.length);
        fileOutputStream.write(pubKey,0,pubKey.length);
    }

    public byte[] serialize() throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream( );
        os.write(iv);
        os.write(mac);
        os.write(pubkey_ephemeral);
        os.write(cipher_text);

        return os.toByteArray();
    }

    public static phrECIES_Message deserialize(byte[] encode) throws phrECIES_Exception {
        if(encode.length < (IV_LEN + MAC_LEN + EMPUB_LEN + CIPHER_BLOCK)) throw new phrECIES_Exception("encode length error");

        int offset= 0;
        byte[] iv= Arrays.copyOfRange(encode, offset, IV_LEN);
        offset += IV_LEN;

        byte[] mac= Arrays.copyOfRange(encode, offset, offset+ MAC_LEN);
        offset += MAC_LEN;

        byte[] pubkey_ephemeral= Arrays.copyOfRange(encode, offset, offset+ EMPUB_LEN);
        offset += EMPUB_LEN;

        byte[] cipher_text= Arrays.copyOfRange(encode, offset, encode.length);

        return new phrECIES_Message(iv, mac, pubkey_ephemeral, cipher_text);
    }

    //will return max 1MB of cipher_text for mac
    public static phrECIES_Message deserialize(FileInputStream fileInputStream,int maxCipherLengthForMac) throws phrECIES_Exception, IOException{
        int length = fileInputStream.available();
        if(length < (HEADER_SIZE + CIPHER_BLOCK)) throw new phrECIES_Exception("encode length error");
        phrECIES.setToCipherPosition(fileInputStream.getChannel(),phrECIES_Message.START_POSITION);

        byte[] iv= new byte[IV_LEN];
        if(fileInputStream.read(iv) <= 0) return null;

        byte[] mac= new byte[MAC_LEN];
        if(fileInputStream.read(mac) <= 0) return null;

        byte[] pubkey_ephemeral= new byte[EMPUB_LEN];
        if(fileInputStream.read(pubkey_ephemeral) <= 0) return null;

        int cipherTextSize = Math.min(length - HEADER_SIZE, maxCipherLengthForMac);
        byte[] cipher_text= new byte[cipherTextSize];
        if(fileInputStream.read(cipher_text) <= 0) return null;

        return new phrECIES_Message(iv, mac, pubkey_ephemeral, cipher_text);
    }

    public byte[] getIV() {return iv; }
    public byte[] getMac() {return mac; }
    public byte[] getPubkeyEphemeral() {return pubkey_ephemeral; }
    public byte[] getCipherText() {return cipher_text; }

    public String toString() {
        String s= "iv: \n"+ Hex.toHexString(iv);

        s+= "\nmac: \n"+ Hex.toHexString(mac);
        s+= "\npubkey_ephemeral: \n"+ Hex.toHexString(pubkey_ephemeral);
        s+= "\ncipher_text: \n"+ Hex.toHexString(cipher_text);

        return s;
    }

}
