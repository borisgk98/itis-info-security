package ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers;

import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.Utils;

import javax.crypto.spec.SecretKeySpec;
import java.lang.ref.Cleaner;
import java.math.BigInteger;

import static ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.DiffieHellmanHelper.G;
import static ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.DiffieHellmanHelper.P;

public class DFMITMNetworkChanel2 implements NetworkChanel {
    private DFClient a, b, m;
    private BigInteger A, B;
    private SecretKeySpec key;
    private DiffieHellmanHelper dh;
    private BigInteger g;
    public static final BigInteger G1 = BigInteger.ONE;
    public static final BigInteger GP = BigInteger.ONE;
    public static final BigInteger GP1 = BigInteger.ONE;

    public DFMITMNetworkChanel2(DFClient a, DFClient b, DFClient m, BigInteger g) {
        this.a = a;
        this.b = b;
        this.m = m;
        this.g = g;
        dh = new DiffieHellmanHelper(P, g);
        B = g.modPow(b.getPrivateKey(), P);
        A = g.modPow(a.getPrivateKey(), P);
        key = dh.generateSymmetricKey(B, a.getPrivateKey());
    }

    @Override
    public void send(Message message, Client from, Client to) {
        if (!(from == b || from == a) && !(to == a || to == b) && a == b) {
            throw new IllegalArgumentException();
        }
        byte[] enrypted = dh.encryptMessage(message.getData(), key);
        // network
        // m intercept message
        byte[] mdecrypted;
        if (g.equals(G1)) {
            mdecrypted = DiffieHellmanHelper.decryptMessage(enrypted, DiffieHellmanHelper.generateSymmetricKey(BigInteger.ONE));
        }
        if (g.equals(GP)) {
            mdecrypted = DiffieHellmanHelper.decryptMessage(enrypted, DiffieHellmanHelper.generateSymmetricKey(BigInteger.valueOf(1L)));
        }
        if (g.equals(GP1)) {
            mdecrypted = DiffieHellmanHelper.decryptMessage(enrypted, DiffieHellmanHelper.generateSymmetricKey(BigInteger.valueOf(1L)));
        }
        else {
            throw new IllegalArgumentException();
        }
        Utils.processDecMess(m, mdecrypted, message);
        // network
        byte[] decrypted = DiffieHellmanHelper.decryptMessage(enrypted, key);
        Utils.processDecMess(to, decrypted, message);
    }
}

