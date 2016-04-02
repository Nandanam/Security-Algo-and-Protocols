import java.util.Scanner;

/*
 * File name : driver.java 
 * Author : Nandanam Vikas 
 * Course : Security-Algo-and-Protocols
 * Assignment : Lab3
 * Due date : 04/01/2016
 * Github repository : https://github.com/Nandanam/Security-Algo-and-Protocols.git
 */

/**
 * driver
 * This is a driver file used for testing
 *
 */
public class driver {
   public static void main(String args[])
	{
		 //System.out.println("Enter the key");
		 Scanner sc = new Scanner(System.in);
	     String input = sc.nextLine();
	    
	     aescipher as = new aescipher();
	     as.makeKeys(input);
	     
	     
	 
	}
	
	
}