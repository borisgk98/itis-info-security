package ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;

import static ru.kpfu.itis.borisgk98.infosecurity.cryptopals.Utils.powMod;
import static ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.DiffieHellmanHelper.G;
import static ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.DiffieHellmanHelper.P;

public class DFNetworkChanel implements NetworkChanel {
    private DFClient a, b;
    private BigInteger A, B;
    private SecretKeySpec key;
    private DiffieHellmanHelper dh;

    public DFNetworkChanel(DFClient a, DFClient b) {
        this.a = a;
        this.b = b;
        dh = new DiffieHellmanHelper(P, G);
        B = G.modPow(b.getPrivateKey(), P);
        A = G.modPow(a.getPrivateKey(), P);
        key = dh.generateSymmetricKey(B, a.getPrivateKey());
    }

    public void send(Message message, Client from, Client to) {
        if (!(from == b || from == a) && !(to == a || to == b) && a == b) {
            throw new IllegalArgumentException();
        }
        byte[] enrypted = dh.encryptMessage(message.getData(), key);
        // network
        byte[] decrypted = DiffieHellmanHelper.decryptMessage(enrypted, key);
        if (message instanceof TextMessage) {
            to.getReceivedMessages().add(new TextMessage(new String(decrypted)));
        }
        else {
            to.getReceivedMessages().add(new BinaryMessage(decrypted));
        }
    }
}
