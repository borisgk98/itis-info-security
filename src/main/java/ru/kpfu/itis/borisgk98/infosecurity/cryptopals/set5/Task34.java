package ru.kpfu.itis.borisgk98.infosecurity.cryptopals.set5;

import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.DFClient;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.DFNetworkChanel;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.NetworkChanel;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.TextMessage;

import java.math.BigInteger;

public class Task34 {
    public static void main(String[] args) {
        DFClient a = new DFClient(BigInteger.valueOf(37L)), b = new DFClient(BigInteger.valueOf(14L));
        NetworkChanel networkChanel = new DFNetworkChanel(a, b);
        networkChanel.send(new TextMessage("kek"), a, b);
        System.out.println(b.getReceivedMessages().get(0));
    }
}
