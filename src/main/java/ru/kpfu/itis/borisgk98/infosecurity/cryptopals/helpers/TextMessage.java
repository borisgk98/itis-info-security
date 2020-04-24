package ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TextMessage implements Message {
    private String text;

    public byte[] getData() {
        return text.getBytes();
    }
}
