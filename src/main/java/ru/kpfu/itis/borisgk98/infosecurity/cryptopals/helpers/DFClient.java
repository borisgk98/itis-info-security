package ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
public class DFClient implements Client {
    private List<Message> receivedMessages = new ArrayList<Message>();
    private BigInteger privateKey;

    public DFClient(BigInteger privateKey) {
        this.privateKey = privateKey;
    }
}
