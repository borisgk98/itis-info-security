package ru.kpfu.itis.borisgk98.infosecurity.kuz;

import org.junit.Before;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;

import static org.junit.Assert.*;

public class GostKuzCryptorTest {

    GostKuzCryptor gostKuzCryptor = new GostKuzCryptor(
            DatatypeConverter.parseHexBinary("8899aabbccddeeff0011223344556677"),
            DatatypeConverter.parseHexBinary("fedcba98765432100123456789abcdef")
    );

    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void x() {
    }

    @Test
    public void s() {
        String[] testData = new String[] { "ffeeddccbbaa99881122334455667700", "559d8dd7bd06cbfe7e7b262523280d39", "0c3322fed531e4630d80ef5c5a81c50b" };
        String[] resultData = new String[] { "b66cd8887d38e8d77765aeea0c9a7efc", "0c3322fed531e4630d80ef5c5a81c50b", "23ae65633f842d29c5df529c13f5acda" };
        for (int i = 0; i < testData.length; i++) {
            assertEquals(DatatypeConverter.printHexBinary(GostKuzCryptor.S(DatatypeConverter.parseHexBinary(testData[i]))), resultData[i].toUpperCase());
        }
    }

    @Test
    public void GFMul() {
    }

    @Test
    public void r() {
        String[] testData = new String[] { "94000000000000000000000000000001", "35940000000000000000000000000000", "64a59400000000000000000000000000" };
        String[] resultData = new String[] { "00000000000000000000000000000100", "94000000000000000000000000000091", "a5940000000000000000000000000000" };
        for (int i = 0; i < testData.length; i++) {
            assertEquals(DatatypeConverter.printHexBinary(GostKuzCryptor.R(DatatypeConverter.parseHexBinary(testData[i]))), resultData[i].toUpperCase());
        }
    }

    @Test
    public void l() {
        String[] testData = new String[] { "d456584dd0e3e84cc3166e4b7fa2890d", "79d26221b87b584cd42fbc4ffea5de9a", "0e93691a0cfc60408b7b68f66b513c13" };
        String[] resultData = new String[] { "64A59400000000000000000000000000", "D456584DD0E3E84CC3166E4B7FA2890D", "79D26221B87B584CD42FBC4FFEA5DE9A" };
        for (int i = 0; i < testData.length; i++) {
            assertEquals(DatatypeConverter.printHexBinary(GostKuzCryptor.L(DatatypeConverter.parseHexBinary(testData[i]))), resultData[i].toUpperCase());
        }
    }

    @Test
    public void reverseS() {
        String[] testData = new String[] { "ffeeddccbbaa99881122334455667700", "559d8dd7bd06cbfe7e7b262523280d39", "0c3322fed531e4630d80ef5c5a81c50b" };
        String[] resultData = new String[] { "b66cd8887d38e8d77765aeea0c9a7efc", "0c3322fed531e4630d80ef5c5a81c50b", "23ae65633f842d29c5df529c13f5acda" };
        for (int i = 0; i < testData.length; i++) {
            assertEquals(DatatypeConverter.printHexBinary(GostKuzCryptor.reverseS(DatatypeConverter.parseHexBinary(resultData[i]))), testData[i].toUpperCase());
        }
    }

    @Test
    public void reverseR() {
        String[] testData = new String[] { "94000000000000000000000000000001", "35940000000000000000000000000000", "64a59400000000000000000000000000" };
        String[] resultData = new String[] { "00000000000000000000000000000100", "94000000000000000000000000000091", "a5940000000000000000000000000000" };
        for (int i = 0; i < testData.length; i++) {
            assertEquals(DatatypeConverter.printHexBinary(GostKuzCryptor.reverseR(DatatypeConverter.parseHexBinary(resultData[i]))), testData[i].toUpperCase());
        }
    }

    @Test
    public void reverseL() {
        String[] testData = new String[] { "d456584dd0e3e84cc3166e4b7fa2890d", "79d26221b87b584cd42fbc4ffea5de9a", "0e93691a0cfc60408b7b68f66b513c13" };
        String[] resultData = new String[] { "64A59400000000000000000000000000", "D456584DD0E3E84CC3166E4B7FA2890D", "79D26221B87B584CD42FBC4FFEA5DE9A" };
        for (int i = 0; i < testData.length; i++) {
            assertEquals(DatatypeConverter.printHexBinary(GostKuzCryptor.reverseL(DatatypeConverter.parseHexBinary(resultData[i]))), testData[i].toUpperCase());
        }
    }

    @Test
    public void f() {
    }

    @Test
    public void computeKeys() {
        String[] resultData = new String[] {
                "8899aabbccddeeff0011223344556677",
                "fedcba98765432100123456789abcdef",
                "3E109D47585364FE5D26CAB3B2B7C914",
                "6A269B36F206F2AAE1AF098362C121F8",
                "9BCC1B5E61128843F36CD956080387C0",
                "74F8409D5A1736E7885379DEAC07865B",
                "9348C8DB728AFE972B34BECD46AE51D4",
                "12DCE103FF645AFE9E57CA72CAED3978",
                "ABAA773101ED4D4609385E4335905BA3",
                "4C9131379210CEBE999193858D73B40E" };
        for (int i = 0; i < gostKuzCryptor.getIter_key().length; i++) {
            assertEquals(DatatypeConverter.printHexBinary(gostKuzCryptor.getIter_key()[i]), resultData[i].toUpperCase());
        }
    }

    @Test
    public void encrypt() {
        String s = "1122334455667700ffeeddccbbaa9988";
        String result = "8B0B594CF77EB752A599D4596B254BDF";
        assertEquals(DatatypeConverter.printHexBinary(gostKuzCryptor.encrypt(DatatypeConverter.parseHexBinary(s))), result.toUpperCase());
    }

    @Test
    public void decrypt() {
        String s = "1122334455667700ffeeddccbbaa9988";
        String result = "8B0B594CF77EB752A599D4596B254BDF";
        assertEquals(DatatypeConverter.printHexBinary(gostKuzCryptor.decrypt(DatatypeConverter.parseHexBinary(result))), s.toUpperCase());
    }
}