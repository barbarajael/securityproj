/**
 * Application - Game "High and Low"
 * Info about organization:
 * - all files related will be stored at /home/$USER/.appfiles
 * -- licenses at /home/$USER/.appfiles/licenses
 * -- requests at /home/$USER/.appfiles/requests
 * -- keys at /home/$USER/.appfiles/keys
 * -- things related with CC at /home/$USER/.appfiles/cc
 * - files will be exchanged by e-mail
 */

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.*;

public class AltoBaixo
{
    protected static final String NAME = "AltoBaixo";
    protected static final String VERSION = "v1.0";

    public static void main (String[] args) throws InvalidKeyException, BadPaddingException,
            NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InterruptedException
    {
        Scanner sc = new Scanner(System.in);
        int choice = -1;

        Biblioteca b = new Biblioteca(AltoBaixo.NAME, AltoBaixo.VERSION);

        System.out.println("WARNING: CC must be inserted through all the process or the app will be closed!");

        // waits for user interaction (gives him time to insert CC)
        System.out.println("Press enter to continue...");
        Scanner keyboard = new Scanner(System.in);
        keyboard.nextLine();

        // check if user is registered
        if( b.isRegistered() == false )
        {
            try
            {
                // try to register the user
                if (b.startRegistration() == true)
                {
                    System.out.println("\nSend a tar.gz of the directory 'appHighNLow' via e-mail to:");
                    System.out.println("- barbara.jael@ua.pt");
                    System.out.println("- david.jorge@ua.pt");
                }

                else
                    System.err.println("ERROR: Registration failed!");
            }

            catch (IOException e) {
                //e.printStackTrace();
                System.err.println("IOException");
            } catch (InterruptedException e) {
                //e.printStackTrace();
                System.err.println("InterruptedException");
            } catch (CertificateException e) {
                //e.printStackTrace();
                System.err.println("CertificateException");
            } catch (UnrecoverableKeyException e) {
                //e.printStackTrace();
                System.err.println("UnrecoverableKeyException");
            } catch (KeyStoreException e) {
                //e.printStackTrace();
                System.err.println("KeyStoreException");
            } catch (SignatureException e) {
                //e.printStackTrace();
                System.err.println("SignatureException");
            } catch (InvalidKeySpecException e) {
                //e.printStackTrace();
                System.err.println("InvalidKeySpecException");
            }
        }

        // if user is already registered
        else
        {
            try
            {
                // check if license's signature is valid
                if (b.validateSignature() == true)
                {
                    // check if license is still valid (validity)
                    if (b.isValid() == true)
                    {
                        // check if the user is really who he says
                        if (b.isReallyUser() == true)
                        {
                            System.out.print("\nShow license or play the game (1 or 2)? ");
                            choice = sc.nextInt();

                            switch (choice) {
                                case 1:
                                    b.showLicenseInfo();
                                    break;
                                case 2:
                                    game();
                                    break;
                                default:
                                    System.err.println("Invalid option!");
                            }
                        }

                        else
                            System.err.println("ERROR: Something does not match with the info in license!");
                    }

                    else
                        System.err.println("ERROR: License's validity has expired!");
                }

                else
                    System.err.println("ERROR: License's signature is not valid!");
            }

            catch (KeyStoreException e) {
                //e.printStackTrace();
                System.err.println("KeyStoreException");
            } catch (CertificateException e) {
                //e.printStackTrace();
                System.err.println("CertificateException");
            } catch (IOException e) {
                //e.printStackTrace();
                System.err.println("IOException");
            } catch (InterruptedException e) {
                //e.printStackTrace();
                System.err.println("InterruptedException");
            } catch (UnrecoverableKeyException e) {
                //e.printStackTrace();
                System.err.println("UnrecoverableKeyException");
            } catch (SignatureException e) {
                //e.printStackTrace();
                System.err.println("SignatureException");
            } catch (ParseException e) {
                //e.printStackTrace();
                System.err.println("ParseException");
            }
        }
    }


    /**
     * METHOD - all done, play the game
     */
    public static void game()
    {
        Scanner sc = new Scanner (System.in);
        Random rand = new Random();

        String answer;
        int num, numTry, counter = 0;

        do {
            /* context */
            System.out.println("\n---------------------------------");
            System.out.printf("%22s\n", "HIGH AND LOW");
            System.out.println(" - Guess the number (1 to 100) - ");
            System.out.println("---------------------------------\n");

            // generates n: 1 <= n <= 100
            num = rand.nextInt(100) + 1;

            do {
                System.out.print("Try: ");
                numTry = sc.nextInt();
                counter++;

                if (numTry < 1 || numTry > 100)
                    System.out.println("Number must be between 1 and 100!");

                else if (numTry > num)
                    System.out.println("Too much");

                else if (numTry < num)
                    System.out.println("Too low");

                System.out.println();

            } while (numTry != num);

            System.out.println("Got it! (" + counter + " tries)");

            System.out.print("Play again? (Y/n): ");
            answer = sc.next();
        } while(!answer.equals("n"));

        sc.close();
    }
}
