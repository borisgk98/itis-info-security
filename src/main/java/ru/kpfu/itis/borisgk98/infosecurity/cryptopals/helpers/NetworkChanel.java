package ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers;

public interface NetworkChanel {
    void send(Message message, Client from, Client to);
}
