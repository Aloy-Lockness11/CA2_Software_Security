
package app;
import java.util.Scanner;

import Utilities.AES;

public class App1 {
    

    public static void main(String[] args) {
        String ENCRYPTED_FILE = "ca2_software_security_aloysius\\Files\\ciphertext.txt";
        String DECRYPTED_FILE = "ca2_software_security_aloysius\\Files\\plaintext.txt";
        Scanner scanner = new Scanner(System.in);

        boolean quit = false;
        while (!quit) {
            System.out.println("Menu:");
            System.out.println("1| Encrypt a File");
            System.out.println("2| Decrypt a File");
            System.out.println("3| Quit the application");
            System.out.print("Enter your choice: ");
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consumes the newline character
            System.out.println();

            switch (choice) {
                case 1:
                    System.out.print("Enter the filename: ");
                    String fileToEncrypt = scanner.nextLine();
                    System.out.print("Enter the secret key: ");
                    String secretKey = scanner.nextLine();
                    try {
                        boolean encryptionResult = AES.encryptFile(fileToEncrypt, ENCRYPTED_FILE, secretKey,false);
                        if (encryptionResult) {
                            System.out.println("File encrypted successfully!! hehe no one can read this now");
                            System.out.println();
                            System.out.println("Encrypted file saved as " + ENCRYPTED_FILE);
                        } else {
                            System.out.println("Error encrypting file");
                        }
                    } catch (Exception e) {
                        System.out.println("Error encrypting file: " + e.getMessage());
                    }
                    break;
                case 2:
                    System.out.print("Enter the filename: ");
                    String encFileName = scanner.nextLine();
                    System.out.print("Enter the secret key: ");
                    String decryptSecretKey = scanner.nextLine();
                    try {
                        boolean decryptionResult = AES.decryptFile(encFileName, DECRYPTED_FILE, decryptSecretKey, true);
                        if (decryptionResult) {
                            System.out.println("File decrypted successfully YAAY! im a hackerman now!!");
                            System.out.println("Decrypted file saved as " + DECRYPTED_FILE);
                        } else {
                            System.out.println("Error decrypting file");
                        }
                    } catch (Exception e) {
                        System.out.println("Error : " + e.getMessage());
                    }
                    break;
                case 3:
                    quit = true;
                    break;
                default:
                    System.out.println("Bruh enter a valid option");
            }
        }

        scanner.close();
    }
}
