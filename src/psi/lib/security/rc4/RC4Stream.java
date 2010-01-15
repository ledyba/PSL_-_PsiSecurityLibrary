package psi.lib.security.rc4;

import psi.lib.security.Stream;

/**
 * @version 1.0
 */
public class RC4Stream implements Cloneable,Stream{
    private int i = 0, j = 0;
    private byte[] key = new byte[RC4_KEY_LENGTH];
    public static final int RC4_KEY_LENGTH = 256;

    public RC4Stream(final byte[] pass) {
        init(pass);
    }
    public void init(final byte[] pass){
        int i, j;
        byte tmp;
        //S�{�b�N�X����
        for (i = 0; i < RC4_KEY_LENGTH; i++) {
            key[i] = (byte)i;
        }
        //�L�[���g���ăV���b�t��
        j = 0;
        for (i = 0; i < RC4_KEY_LENGTH; i++) {
            j = (j + key[i] + pass[i]) & 0xff;
            tmp = key[i];
            key[i] = key[j];
            key[j] = tmp;
        }
    }

    public byte getNext() {
        int i = this.i;
        int j = this.j;
        byte tmp;
        //�C���f�b�N�X�̃Z�b�g
        i = (i + 1) & 0xff;
        j = (j + key[i]) & 0xff;
        this.i = i;
        this.j = j;
        //���ւ�
        tmp = key[i];
        key[i] = key[j];
        key[j] = tmp;
        return key[(key[i] + key[j]) & 0xff];
    }
    public void getArray(byte[] b){
        for(int i=0;i<b.length;i++){
            b[i] = getNext();
        }
    }
    public void copy(RC4Stream str){
        str.i = this.i;
        str.j = this.j;
        for(int i=0;i<RC4_KEY_LENGTH;i++){
            str.key[i] = this.key[i];
        }
    }
}
