
import java.util.Scanner;

/*
 *  Nandanam Vikas 
 * Github repository : https://github.com/Nandanam/Security-Algo-and-Protocols.git
 */

/**
 * This is a driver file used for testing
 *
 * @author vky
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

