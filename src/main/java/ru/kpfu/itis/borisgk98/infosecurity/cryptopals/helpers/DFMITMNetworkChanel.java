package ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers;

public class DFMITMNetworkChanel implements NetworkChanel {
    private DFClient a, b, m;
    private DFNetworkChanel am, mb;

    public DFMITMNetworkChanel(DFClient a, DFClient b, DFClient m) {
        this.a = a;
        this.b = b;
        this.m = m;
        am = new DFNetworkChanel(a, m);
        mb = new DFNetworkChanel(m, b);
    }

    @Override
    public void send(Message message, Client from, Client to) {
        if (from == a) {
            am.send(message, a, m);
            mb.send(message, m, b);
        }
        else {
            mb.send(message, b, m);
            am.send(message, m, a);
        }
    }
}
