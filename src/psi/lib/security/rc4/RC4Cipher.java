package psi.lib.security.rc4;
import java.io.OutputStream;
import java.io.IOException;
import java.io.InputStream;
import psi.lib.security.Cipher;

/**
 * @version 1.0
 */

public class RC4Cipher implements Cipher{

    private RC4Stream MasterStream;
    private RC4Stream Backup;
    private RC4Stream Stream;
    byte[] next_buff = new byte[RC4Stream.RC4_KEY_LENGTH];

    public RC4Cipher(byte[] def){
        MasterStream = new RC4Stream(def);
        MasterStream.getArray(this.next_buff);
        Backup = new RC4Stream(this.next_buff);
    }

    private byte encrypt_char(byte n) {
        byte k = Stream.getNext();
        n = (byte)(n & 0xff);
        return (byte)(n ^ k);
    }

    private byte decrypt_char(byte n) {
        byte k = Stream.getNext();
        n ^= k;
        return (byte)(n & 0xff);
    }

    //Input
    public byte[] decData(byte[] data, int off, int len) {
        int i;
        for (i = off; i < off + len; i++) {
            data[i] = decrypt_char(data[i]);
        }
        return data;
    }

    public int decData(InputStream is, byte[] data, int off, int len) throws
            IOException {
        int size = is.read(data, off, len);
        data = decData(data, off, size);
        return size;
    }

    public int decData(InputStream is, byte[] data) throws IOException {
        return decData(is, data, 0, data.length);
    }

    //Output
    public byte[] encData(byte[] data, int off, int len) {
        int i;
        for (i = off; i < off + len; i++) {
            data[i] = encrypt_char(data[i]);
        }
        return data;
    }

    public void encData(OutputStream os, byte[] data, int off, int len) throws
            IOException {
        data = encData(data, off, len);
        os.write(data, off, len);
    }

    public void encData(OutputStream os, byte[] data) throws IOException {
        encData(os, data, 0, data.length);
    }

    public void startCrypt() {
        Backup.copy(Stream);
    }
    public void nextStream() {
        MasterStream.getArray(next_buff);
        Backup.init(this.next_buff);
    }
}
