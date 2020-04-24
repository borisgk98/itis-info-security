package ru.kpfu.itis.borisgk98.infosecurity.cryptopals.set5;

import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.DFClient;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.DFMITMNetworkChanel2;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.DFNetworkChanel;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.NetworkChanel;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.TextMessage;

import java.math.BigInteger;

import static ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.DiffieHellmanHelper.P;

public class Task35 {
    public static void main(String[] args) {

        DFClient a = new DFClient(BigInteger.valueOf(37L)), b = new DFClient(BigInteger.valueOf(14L));
        DFClient m = new DFClient(BigInteger.valueOf(13L));
        NetworkChanel networkChanel = new DFMITMNetworkChanel2(a, b, m, DFMITMNetworkChanel2.G1);
        networkChanel.send(new TextMessage("test"), a, b);
        System.out.println(b.getReceivedMessages());
        System.out.println(m.getReceivedMessages());

        networkChanel = new DFMITMNetworkChanel2(a, b, m, DFMITMNetworkChanel2.GP);
        networkChanel.send(new TextMessage("test"), a, b);
        System.out.println(b.getReceivedMessages());
        System.out.println(m.getReceivedMessages());

        networkChanel = new DFMITMNetworkChanel2(a, b, m, DFMITMNetworkChanel2.GP1);
        networkChanel.send(new TextMessage("test"), a, b);
        System.out.println(b.getReceivedMessages());
        System.out.println(m.getReceivedMessages());
    }
}
