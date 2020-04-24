package ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class BinaryMessage implements Message {
    private byte[] data;
}
