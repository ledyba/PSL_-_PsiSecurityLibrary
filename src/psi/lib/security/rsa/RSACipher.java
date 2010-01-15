package psi.lib.security.rsa;

import java.io.*;

import psi.lib.security.*;
import java.math.BigInteger;

/**
 */
public class RSACipher implements Cipher {
    private RSAKeyPair KeyPair;
    private final int KeyLength;
    private final int BlockSize;
    /**
     * �閧�����܂߂č���B�N���C�A���g�p�B
     * @param key_length int
     * @param power_length int
     * @throws IOException
     */
    public RSACipher(int key_length, int power_length) throws IOException {
        if (((key_length | power_length) & 15) != 0) {
            throw new IOException("�r�b�g����16�̔{���ɂ��ĉ������B");
        }
        key_length >>= 1;//module�̃r�b�g�� = key_length * 2
        KeyPair = new RSAKeyPair(key_length, power_length);
        KeyLength = key_length >> 3;
        BlockSize = KeyLength << 1;
    }
    /**
     * ���J����o�^�ł���B�T�[�o�p
     * @param power_public byte[]
     * @param module byte[]
     * @throws IOException
     */
    public RSACipher(int power_length,byte[] power_public,
                     int module_length,byte[] module) throws IOException {
        KeyPair = new RSAKeyPair(power_length,power_public, module_length,module);
        KeyLength = module_length >> 4;
        BlockSize = module_length >> 3;
    }
    public RSAKeyPair getKeyPair(){
        return this.KeyPair;
    }

    /**
     * encData
     *
     * @param data byte[]
     * @param off int
     * @param len int
     * @return byte[]
     */
    public byte[] encData(byte[] data, int off, int len) throws IOException {
        byte[] buff = new byte[KeyLength];
        int block_num = len / KeyLength;
        if ((len % KeyLength) != 0) {
            block_num++;
        }
        byte[] out_data = new byte[block_num * BlockSize];
        int data_index = off;
        int out_index = 0;
        int end = off + len;
        for (int i = 0; i < block_num; i++) {
            int buff_size = Math.min(KeyLength, end - data_index);
            System.arraycopy(data, data_index, buff, 0,buff_size);
            for(int j=buff_size;j<KeyLength;j++){
                buff[j] = 0;
            }
            BigInteger block = new BigInteger(1, buff);
            block = block.modPow(KeyPair.getPowerPublic(), KeyPair.getModule());
            byte[] out = block.toByteArray();
            if (!((out.length <= BlockSize && ((out[0] & 0x80) == 0)) ||
                  ((out.length == BlockSize + 1) && out[0]  == 0))) {
                throw new IOException("�Í����������ʂ��u���b�N�T�C�Y�ȏ�ł��B���肦�Ȃ��B");
            }
            int length = Math.min(BlockSize, out.length);
            System.arraycopy(out, out.length - length, out_data, out_index,
                             length);
            data_index += KeyLength;
            out_index += BlockSize;
        }
        return out_data;
    }

    /**
     * decData
     *
     * @param data byte[]
     * @param off int
     * @param len int
     * @return byte[]
     */
    public byte[] decData(byte[] data, int off, int len) throws IOException {
        byte[] buff = new byte[BlockSize];
        int block_num = len / BlockSize;
        if ((len % BlockSize) != 0) {
            block_num++;
        }
        byte[] out_data = new byte[block_num * KeyLength];
        int data_index = off;
        int out_index = 0;
        int end = off + len;
        for (int i = 0; i < block_num; i++) {
            int buff_size = Math.min(BlockSize, end - data_index);
            System.arraycopy(data, data_index, buff, 0,buff_size);
            for(int j=buff_size;j<BlockSize;j++){
                buff[j] = 0;
            }
            BigInteger block = new BigInteger(1, buff);
            block = block.modPow(KeyPair.getPowerSecret(), KeyPair.getModule());
            byte[] out = block.toByteArray();
            if (!((out.length <= KeyLength && ((out[0] & 0x80) == 0)) ||
                  ((out.length == KeyLength + 1) && out[0] == 0))) {
                throw new IOException("�����������ʂ��L�[�T�C�Y�ȏ�ł��B���肦�Ȃ��B");
            }
            int length = Math.min(KeyLength, out.length);
            System.arraycopy(out, out.length - length, out_data, out_index,
                             length);
            data_index += BlockSize;
            out_index += KeyLength;
        }
        return out_data;
    }
}
