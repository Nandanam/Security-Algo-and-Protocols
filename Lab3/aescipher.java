
/**
 * file: aescipher.java
 * author : Nandanam Vikas 
 * course : Security Algorithms and Protocols
 * assignment : lab3
 * due date : 04/1/2016
 * Git hub repository : https://github.com/Nandanam/Security-Algo-and-Protocols.git
 *
 * This file contains all the declarations.
 */
 
 /**
  * aescipher
  * This class generates 11 round keys.
  */
 
 
public class aescipher {

        /**
	 * SBOX
	 * This method stores look up table S-box.
	 */
    private static final String[][] SBOX = {
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
	 * RCON
	 * This method stores round constants look up table.
	 */
    private static final String[][] RCON = {
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
    
    // Stores 4x4 matrix.
    private static String[][] key = new String[4][4];
	
    // Stores 4x44 matrix.
    public static String[][] matrix_W = new String[4][44];
	
    
    /**
     * addKey
     * 
     * The method addKey takes string(plain text) and key as input.
     * This does xoring of key and plain text and generates a 4X4 matrix.
     * 
     * Parameter:
     * akMatrix = stores the result of message and key in matrix form.  
     * This method returns akMatrix.
     */
    
    public static String[][] addKey(String sHex, String kHex){
        String[][] akMatrix = new String[4][4];      
        String out = functionXOR(sHex, kHex);
        System.out.println(out);
        int i =0;
		for (int col1 = 0; col1 <=3; col1++) {			
                    for (int row1 = 0; row1 <=3; row1++) {
			akMatrix[row1][col1] = out.substring(i,i+2);
			i=i+2;
                    }               
		}
        return akMatrix;
        }
    
    /**
     * aesNibbleSubstitution
     * 
     * This method performs substitution operation by looking up at SBOX.
     * 
     *  This returns inStateHex.
     */
    public static String[][] aesNibbleSubstitution(String[][] inStateHex){
        for(int i =0 ; i<1; i++){
            for(int j =0; j<=3 ; j++){
                int x = Integer.parseInt(inStateHex[i][j].split("")[0],16);
                int y = Integer.parseInt(inStateHex[i][j].split("")[0],16);
                           
                     inStateHex[i][j] = SBOX[x][y];                                              
	            }
            }
        return inStateHex;
    }
    
    /**
     * aesShiftRow
     * 
     * This method performs shifting of rows.
     * In this shifting process the except the first row all rows are shifted.
     * Shifting is performed by the following way:
     * Second row is shifted by one value.
     * Third row is shifted by two values.
     * Final row is shifted by three values.
     * 
     * This method returns outStateHex.
     */
     public static String[][] aesShiftRow(String[][]inStateHex){
        String[][] outStateHex = new String[4][4];
        int count=0;
         for (int m=0; m<4; m++) {
           for(int n=0;n<4;n++){
             outStateHex[m][n] = inStateHex[m][(n+count)%4];
           } 
           count++;
        }
        return outStateHex;
        }
	
        /**
	 * makeKeys
         * 
	 * This method calls takeGivenKey method which has initial 4x4 matrix
	 * This method takes 4x4 matrix as input and generates a 4x44 matrix.
	 * In this method Xoring is done with RCON. 
	 * 
	 * Parameters:
	 *   w_New : is temporary matrix which stores a 4x44 matrix.
         *   keyRound : is a number for counting number of rounds 	 
	 * 
         */
    public static void makeKeys(String input) {

         takeGivenKey(input);
         
         for (int row = 0; row <= 3; row++) {
            for (int column = 0; column <= 3; column++) {
                matrix_W[row][column] = key[row][column];
            }
        }
       
        // Creating 4x44 matrix as w_New
        String[][] w_New = null;
        for (int column = 4; column <= 43; column++) {
 //Checking the condition to generate 4x44 matrix,if column is not multiple of 4 
            if (column % 4 != 0) {
                for (int row = 0; row <= 3; row++) {
                matrix_W[row][column] = functionXOR(matrix_W[row][column - 4], 
                        matrix_W[row][column - 1]);
                }
            } else {
                // w_New is a temporary matrix
                w_New = new String[1][4];

                w_New[0][0] = matrix_W[0][column - 1];
                w_New[0][1] = matrix_W[1][column - 1];
                w_New[0][2] = matrix_W[2][column - 1];
                w_New[0][3] = matrix_W[3][column - 1];

                // Shift to the left of column values of w_New
                w_New[0][0] = matrix_W[1][column - 1];
                w_New[0][1] = matrix_W[2][column - 1];
                w_New[0][2] = matrix_W[3][column - 1];
                w_New[0][3] = matrix_W[0][column - 1];

                // transform each of the four bytes in w_New using an S-box function
                for (int m = 0; m < 1; m++) {
                    for (int n = 0; n <= 3; n++) {
                        w_New[m][n] = aesSbox(w_New[m][n]);
                    }
                }

                
                //find number of round and XOR with RCON
                int keyRound = column / 4;
                //get RCon of the same column number form Rcon table and xOR with first element
                w_New[0][0] = functionXOR(RCON[0][keyRound], w_New[0][0]);

                
                for (int row = 0; row <= 3; row++) {
                 matrix_W[row][column] = functionXOR(matrix_W[row][column - 4],
                    w_New[0][row]);
                }
            }
        }
       
	   // Counts the round keys for generating 11 keys.
        int count = 1;
        int column = 0;
        while (count <= 11) {
            for (int k = 0; k <= 3; k++, column++) {
                for (int row = 0; row <= 3; row++) {
                    System.out.print(matrix_W[row][column]);
                }
            }
            System.out.println();
            count++;
        }
        System.out.println("");
    }
    
    /**
     * aesSbox
     * 
     * This method performs look up  operation .
     * 
     * This method returns output
     *  
     */
    public static String aesSbox(String in) {
        int Sboxa = Integer.parseInt(in.split("")[0], 16);
        int Sboxb = Integer.parseInt(in.split("")[1], 16);
        String output = SBOX[Sboxa][Sboxb];
        return output;
    }
        /**
	 * functionXOR
         * 
	 * This method does the Xoring and returns result.
	 * This method is called in makeKeys to perform XOR.
	 *
	 */
    public static String functionXOR(String i, String j) {
        int Digit1 = Integer.parseInt(i, 16);
        int Digit2 = Integer.parseInt(j, 16);
        int XOR = Digit1 ^ Digit2;
        String result = Integer.toHexString(XOR);
        if (result.length() == 1) {
            result = "0" + result;
        }
        return result;
    }
	
	/**
	 * takeGivenKey
         * 
	 * This method is used for forming an initial 4x4 matrix.
	 * The matrix is formed by taking a key as input.
	 */
    public static void takeGivenKey(String input){

       //Forming the initial 4x4 matrix
        int i = 0;
        for (int column = 0; column < 4; column++) {
            for (int row = 0; row < 4; row = row + 1) {
                key[row][column] = input.substring(i, i + 2);
                i = i + 2;
            }
        }
        
}
}
