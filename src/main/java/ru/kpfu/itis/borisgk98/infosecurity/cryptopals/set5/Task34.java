package ru.kpfu.itis.borisgk98.infosecurity.cryptopals.set5;

import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.DFClient;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.DFMITMNetworkChanel;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.DFNetworkChanel;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.NetworkChanel;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.TextMessage;

import java.math.BigInteger;

import static ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.DiffieHellmanHelper.P;

public class Task34 {
    public static void main(String[] args) {
        DFClient a = new DFClient(BigInteger.valueOf(37L)), b = new DFClient(BigInteger.valueOf(14L));
        NetworkChanel networkChanel = new DFNetworkChanel(a, b);
        networkChanel.send(new TextMessage("test"), a, b);
        System.out.println(b.getReceivedMessages());

        DFClient m = new DFClient(P);
        NetworkChanel mitmChanel = new DFMITMNetworkChanel(a, b, m);
        mitmChanel.send(new TextMessage("test"), a, b);
        System.out.println(m.getReceivedMessages());
        System.out.println(b.getReceivedMessages());
    }
}
