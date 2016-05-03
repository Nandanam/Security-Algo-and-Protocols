package com.example.vky.aes;

import android.widget.Switch;

import java.math.BigInteger;

/**
 * This class is responsible for Encrypting a plain text into a ciphertext.
 * Implements various operations of AES, such as Round key generation, SBOX substitution,
 * Shifting rows, Mixing columns to randomize the encryption to a complex level for better security
 *
 * @author Vikas Nandanam, Vikram Patil
 */

public class Aescipher {
    /**
     * S_BOX static String 2d array used for s-box transformations
     */
    private static final String[][] S_BOX = {
            {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76"},
            {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0"},
            {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15"},
            {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},
            {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},
            {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},
            {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},
            {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},
            {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},
            {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},
            {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},
            {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},
            {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},
            {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},
            {"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},
            {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"}};

    /**
     * R_CON static String 2d array used for r-con transformations
     */

    private static final String[][] R_CON = {
            {"8D", "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36", "6C", "D8", "AB", "4D", "9A"},
            {"2F", "5E", "BC", "63", "C6", "97", "35", "6A", "D4", "B3", "7D", "FA", "EF", "C5", "91", "39"},
            {"72", "E4", "D3", "BD", "61", "C2", "9F", "25", "4A", "94", "33", "66", "CC", "83", "1D", "3A"},
            {"74", "E8", "CB", "8D", "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36", "6C", "D8"},
            {"AB", "4D", "9A", "2F", "5E", "BC", "63", "C6", "97", "35", "6A", "D4", "B3", "7D", "FA", "EF"},
            {"C5", "91", "39", "72", "E4", "D3", "BD", "61", "C2", "9F", "25", "4A", "94", "33", "66", "CC"},
            {"83", "1D", "3A", "74", "E8", "CB", "8D", "01", "02", "04", "08", "10", "20", "40", "80", "1B"},
            {"36", "6C", "D8", "AB", "4D", "9A", "2F", "5E", "BC", "63", "C6", "97", "35", "6A", "D4", "B3"},
            {"7D", "FA", "EF", "C5", "91", "39", "72", "E4", "D3", "BD", "61", "C2", "9F", "25", "4A", "94"},
            {"33", "66", "CC", "83", "1D", "3A", "74", "E8", "CB", "8D", "01", "02", "04", "08", "10", "20"},
            {"40", "80", "1B", "36", "6C", "D8", "AB", "4D", "9A", "2F", "5E", "BC", "63", "C6", "97", "35"},
            {"6A", "D4", "B3", "7D", "FA", "EF", "C5", "91", "39", "72", "E4", "D3", "BD", "61", "C2", "9F"},
            {"25", "4A", "94", "33", "66", "CC", "83", "1D", "3A", "74", "E8", "CB", "8D", "01", "02", "04"},
            {"08", "10", "20", "40", "80", "1B", "36", "6C", "D8", "AB", "4D", "9A", "2F", "5E", "BC", "63"},
            {"C6", "97", "35", "6A", "D4", "B3", "7D", "FA", "EF", "C5", "91", "39", "72", "E4", "D3", "BD"},
            {"61", "C2", "9F", "25", "4A", "94", "33", "66", "CC", "83", "1D", "3A", "74", "E8", "CB", "8D"}};

    //userKey->For user given key
    //userText->For user given text
    private static String[][] userKey = new String[4][4];
    private static String[][] userText = new String[4][4];

    // allKeysMatrix is for saving 10 round keys along with original key
    public static String[][] allKeysMatrix = new String[4][44];

    //GMatrix is used for Mixing columns
    static String[][] GMatrix =
            {
                    {"02", "03", "01", "01"},
                    {"01", "02", "03", "01"},
                    {"01", "01", "02", "03"},
                    {"03", "01", "01", "02"}
            };

    /**
     * This method is responsible for generating a hexadecimal String for a normal String
     *
     * @param arg- takes a String input to convert it to a hexadecimal String
     * @return returns a Hexadecimal String
     */
    public static String toHex(String arg) {

        return String.format("%x", new BigInteger(1, arg.getBytes(/*YOUR_CHARSET?*/)));
    }

    /**
     * This method is responsible for generating a normal String for a hexadecimal String
     *
     * @param arg takes a hexadecimal String input to convert it to a String
     * @return returns a normal String
     */
    public static String unHex(String arg) {
        String str = "";
        for (int i = 0; i < arg.length(); i += 2) {
            String s = arg.substring(i, (i + 2));
            int decimal = Integer.parseInt(s, 16);
            str = str + (char) decimal;
        }
        return str;
    }

    /**
     * This method is called from Activity1.java to encrypt plaintext with a user sent key
     *
     * @param a Key sent by the user on UI
     * @param b Plaintext sent by user on UI
     * @return Returns a Hexadecimal String as ciphertext
     */
    public static String aes(String a, String b) {
        String key = toHex(a);
        String plaintext = toHex(b);
        String cipher = "";
        int i = 0;
        int j = 0;
        for (int column = 0; column < 4; column++) {
            for (int row = 0; row < 4; row++) {
                userKey[row][column] = key.substring(i, i + 2);
                i = i + 2;
            }
        }
        // Making all round keys
        generateAllKeys();
        //Taking userText and converting to 4x4 matrix
        for (int column = 0; column < 4; column++) {
            for (int row = 0; row < 4; row = row + 1) {
                userText[row][column] = plaintext.substring(j, j + 2);
                j = j + 2;
            }
        }
        // Extracting Key i.e. 4x4 matrix from allKeysMatrix to perform AES internal functions.
        String[][] keyHex = new String[4][4];
        int WCol = 0;
        int roundCounter = 0;
        while (WCol < 44) {
            for (int cols = 0; cols < 4; cols++, WCol++) {
                for (int row = 0; row < 4; row++) {
                    keyHex[row][cols] = allKeysMatrix[row][WCol];
                }
            }
            if (roundCounter != 10) {
                roundCounter++;
                userText = aesStateXor(userText, keyHex);
                userText = aesNibbleSub(userText);
                userText = aesShiftRow(userText);
                if (roundCounter != 10)
                    userText = aesMixColumn(userText);
            } else
                // For 10th Round
                userText = aesStateXor(userText, keyHex);
        }
        //Saving encrypted text in a String
        for (int cols = 0; cols < 4; cols++) {
            for (int row = 0; row < 4; row++) {
                cipher = cipher + userText[row][cols];
            }
        }
        return cipher;
    }

    /**
     * This method generates All round keys and saves it in allKeysMatrix
     * This operation is the start point of the AES encryption
     */
    public static void generateAllKeys() {
        // Saving the user key in keyMatrixW by filling the first 4*4 cells
        for (int row = 0; row < 4; row = row + 1) {
            System.arraycopy(userKey[row], 0, allKeysMatrix[row], 0, 4);
        }
        // Temporary matrix used to save a shifted cell matrix from the round key matrix
        String[][] temporaryMatrix;
        for (int column = 4; column < 44; column++) {
            // When column is not a multiple of 4
            if (column % 4 != 0) {
                for (int row = 0; row < 4; row++) {
                    allKeysMatrix[row][column] = XOR(allKeysMatrix[row][column - 4],
                            allKeysMatrix[row][column - 1]);
                }
            } else {
                // If column is a multiple of 4
                temporaryMatrix = new String[1][4];
                // shifting cells in the temporary matrix
                temporaryMatrix[0][0] = allKeysMatrix[1][column - 1];
                temporaryMatrix[0][1] = allKeysMatrix[2][column - 1];
                temporaryMatrix[0][2] = allKeysMatrix[3][column - 1];
                temporaryMatrix[0][3] = allKeysMatrix[0][column - 1];
                // Once the shifting is done we do the s-box transformation
                for (int i = 0; i < 1; i++) {
                    for (int j = 0; j < 4; j++) {
                        temporaryMatrix[i][j] = aesSbox(temporaryMatrix[i][j]);
                    }
                }
                //for every round taking r to refer in Rcon table
                int r = column / 4;
                temporaryMatrix[0][0] = XOR(aesRcon(r), temporaryMatrix[0][0]);
                // Last XORing of keys and the temporary matrix
                for (int row = 0; row < 4; row++) {
                    allKeysMatrix[row][column] = XOR(allKeysMatrix[row][column - 4],
                            temporaryMatrix[0][row]);
                }
            }
        }
    }

    /**
     * Performs exclusive or on the key and plain text and returns a Matrix
     *
     * @param sHex   PlainText matrix(transformed)
     * @param keyHex Round Key
     * @return Returns a String 2d array or a matrix after XOR
     */
    public static String[][] aesStateXor(String[][] sHex, String[][] keyHex) {
        String XORMatrix[][] = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                XORMatrix[i][j] = XOR(sHex[i][j], keyHex[i][j]);
            }
        }
        return XORMatrix;
    }

    /**
     * Accepts Exclusiveor output and finds the respective element in S_BOX matrix
     *
     * @param pText Transformed plaintext for Nibble substitution from the SBOX
     * @return Returns String 2d array after substitution
     */
    public static String[][] aesNibbleSub(String[][] pText) {
        String nibbleSubValues[][] = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                nibbleSubValues[i][j] = aesSbox(pText[i][j]);
            }
        }
        return nibbleSubValues;
    }

    /**
     * Once the S_BOX values are returned they are shifted
     *
     * @param inHex transformed plaintext
     * @return Returns a String 2d array after shifting rows
     */
    public static String[][] aesShiftRow(String[][] inHex) {
        String[][] outHex = new String[4][4];
        int count = 4;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                if (i > 0) {
                    outHex[i][(j + count) % 4] = inHex[i][j];
                } else {
                    outHex[i][j] = inHex[i][j];
                }
            }
            count--;
        }
        return outHex;
    }

    /**
     * called from mix columns method if the element is to be multiplied with 2
     *
     * @param inHex Transformed plaintext for shifting and padding
     * @return Returns a String after shifting
     */
    protected static String mul2(String inHex) {
        inHex = Integer.toBinaryString(Integer.parseInt(inHex, 16));
        int inHexLenght = 8 - (inHex.length());
        String padding = new String();
        for (int i = 0; i < inHexLenght; i++) {
            padding += "0";
        }
        String in = padding.concat(inHex);
        String hex = Integer.toHexString(27);
        String shiftedBinary = Integer.toBinaryString(Integer.parseInt(in, 2) << 1);

        if (shiftedBinary.length() > 8)
            shiftedBinary = shiftedBinary.substring(1);
        String afterShift = Integer.toHexString(Integer.parseInt(shiftedBinary, 2));

        if (in.substring(0, 1).equals("1")) {
            return XOR(afterShift, hex);
        } else
            return afterShift;
    }

    /**
     * This function XORs the output of mul2 method with the inHex
     *
     * @param inHex Transformed plaintext to be XORed and multiplied after shift
     * @return Returns a string after XOR of product of mul2 method and inHex
     */
    protected static String mul3(String inHex) {
        return XOR(mul2(inHex), inHex);
    }

    /**
     * Once the shifting is done mixing operation will be performed
     *
     * @param inHex Transformed plaintext to for mixing columns
     * @return Returns a String Matrix after mixing columns
     */
    protected static String[][] aesMixColumn(String[][] inHex) {
        String sum;
        String output[][] = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                sum = "0";
                for (int k = 0; k < 4; k++) {
                    // checks Galois matrix to perform different operations
                    switch (GMatrix[i][k]) {
                        case "01":
                            sum = XOR(sum, inHex[k][j]);
                            break;
                        case "02":
                            sum = XOR(sum, mul2(inHex[k][j]));
                            break;
                        case "03":
                            sum = XOR(sum, mul3(inHex[k][j]));
                            break;
                    }
                }

                output[i][j] = sum;
            }
        }
        return output;
    }

    /**
     * This method is to perform XOR between two Strings
     *
     * @param val1 : First String
     * @param val2 : second String
     * @return : Returns hexadecimal String
     */
    private static String XOR(String val1, String val2) {
        int Value1 = Integer.parseInt(val1, 16);
        int Value2 = Integer.parseInt(val2, 16);
        int exclusiveOutput = Value1 ^ Value2;
        String hexResult = Integer.toHexString(exclusiveOutput);
        return hexResult.length() == 1 ? ("0" + hexResult) : hexResult;
    }

    /**
     * This method takes a String and performs SBOX substitution
     *
     * @param inSBox : String which is split and used as index on s_box
     * @return : Returns the value from s-box matrix
     */
    public static String aesSbox(String inSBox) {
        int firstDigitInt = Integer.parseInt(inSBox.substring(0, 1), 16);
        int secondDigitInt = Integer.parseInt(inSBox.substring(1, 2), 16);
        String outSBox = S_BOX[firstDigitInt][secondDigitInt];
        return outSBox;
    }

    /**
     * This method takes a String and returns an element from R_CON table
     *
     * @param inR_CON : Index to lookup in R_CON matrix
     * @return : Value from the R_CON matrix
     */
    public static String aesRcon(int inR_CON) {

        String outR_CON = R_CON[0][inR_CON];
        return outR_CON;
    }

}