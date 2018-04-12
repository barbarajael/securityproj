/**
 * Author's plataform
 * - constructor
 * - methods:
 * -- main(): void
 * -- createPaths(): void
 * -- validateSignature(): boolean
 * -- readRequest(): String
 * -- printRequest(String request): void
 * -- makeLicense(String request): void
 * -- signLicense (File tmpLicense): void
 * Notes about files:
 * - the author is responsible for keeping the files in the right place
 * (the existence of files is not checked);
 * - the author is responsible for giving the files with the right permissions.
 */

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.*;
import java.text.SimpleDateFormat;
import java.util.*;


public class Author
{
    /* paths needed */

    private static String origin = System.getProperty("user.home");
    private static String path_app =  origin + "/appFiles";
    private static String path_requests = path_app + "/requests";
    private static String path_licenses = path_app + "/licenses";
    private static String path_keys = path_app + "/keys";
    private static String path_cc = path_app + "/cc";

    private static String userSignature = path_cc + "/userSignature";
    private static String ccUserCert = path_cc + "/ccUserCert";

    private static String rsaPrivateKey = path_keys + "/privateKey";
    private static String cipheredRequest = path_requests + "/cipheredRequest";
    private static String ivFile = path_keys + "/IV";
    private static String cipheredSessionKey = path_keys + "/cipheredSessionKey";

    private static String authorSignature = path_cc + "/authorSignature";
    private static String ccAuthorCert = path_cc + "/ccAuthorCert";


    /* ------------------ */


    public static void main (String[] args)
    {
        createPaths();

        String request = null;
        String answer;
        Scanner sc = new Scanner (System.in);

        File fReq = new File(cipheredRequest);
        if (!fReq.exists())
        {
            System.err.println("There are no requests or you haven't organized them.");
            System.exit(0);
        }

        try {
            //check if the request's signature is valid
            if (validateSignature() == true)
            {
                /* read request */
                try {
                    request = readRequest();
                }

                catch (IOException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (InvalidKeySpecException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (InvalidAlgorithmParameterException e) {
                    e.printStackTrace();
                } catch (NoSuchProviderException e) {
                    e.printStackTrace();
                }


                /* print request file (deciphered and decoded) */

                printRequest(request);


                /* make license */

                System.out.print("\nMake license for this request? (y/N) ");
                answer = sc.nextLine();

                if (answer.equals("y")) {
                    try {
                        makeLicense(request);
                    }

                    catch (KeyStoreException e) {
                        e.printStackTrace();
                    } catch (CertificateException e) {
                        e.printStackTrace();
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    } catch (UnrecoverableKeyException e) {
                        e.printStackTrace();
                    } catch (InvalidKeyException e) {
                        e.printStackTrace();
                    } catch (SignatureException e) {
                        e.printStackTrace();
                    }
                }
            }

            else
                System.err.println("ERROR: Request's signature is not valid!");
        }

        catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }


    /**
     * METHOD createPaths - create all paths (if non-existent)
     */
    private static void createPaths()
    {
        // directories
        File dir_app = new File(path_app);
        File dir_requests = new File(path_requests);
        File dir_licenses = new File(path_licenses);
        File dir_keys = new File(path_keys);
        File dir_cc = new File(path_cc);

        // if don't exist, create
        if (!dir_app.isDirectory())
            new File(path_app).mkdir();
        if (!dir_requests.isDirectory())
            new File(path_requests).mkdir();
        if (!dir_licenses.isDirectory())
            new File(path_licenses).mkdir();
        if (!dir_keys.isDirectory())
            new File(path_keys).mkdir();
        if (!dir_cc.isDirectory())
            new File(path_cc).mkdir();
    }


    /**
     * METHOD validateSignature - verifies user's  signature
     * @return true is the user signature is valid
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws UnrecoverableKeyException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    private static boolean validateSignature() throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException, UnrecoverableKeyException,
            InvalidKeyException, SignatureException
    {
        /* read files */

        // read user's cc cert file
        FileInputStream usercert = new FileInputStream(ccUserCert);
        byte[] certB = new byte[usercert.available()];
        usercert.read(certB);
        usercert.close();

        // read license file
        FileInputStream fis = new FileInputStream(cipheredRequest);
        byte[] fileB = new byte[fis.available()];
        fis.read(fileB);

        // read signature file
        FileInputStream fsig = new FileInputStream(userSignature);
        byte[] sigB = new byte[fsig.available()];
        fsig.read(sigB);
        fsig.close();


        /* CC things */

        // get certificate
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(certB);
        Certificate cert = (Certificate) certFactory.generateCertificate(in);

        // get CC user key
        PublicKey pubKeyUser = (PublicKey) cert.getPublicKey();


        /* verify signature */

        // verify signature with the CC user public key
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(pubKeyUser);

        // supply signature with data to be verified
        BufferedInputStream bufin = new BufferedInputStream(fis);
        byte[] buffer = new byte[1024];
        int len;
        while (bufin.available() != 0)
        {
            len = bufin.read(buffer);
            signature.update(buffer, 0, len);
        }

        fis.close();
        bufin.close();

        // verify
        if(!signature.verify(sigB))
            return false;
        else
            return true;
    }


    /**
     * METHOD readRequest - reads registration request
     * request file is deciphered and then decoded (from base64)
     * after checking the request, decides if wants to make the license
     * @return Request deciphered and decoded
     * @throws IOException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     */
    private static String readRequest() throws IOException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
            InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, NoSuchProviderException
    {
        /* get RSA 1024 private key */

        // read private key from file
        FileInputStream privK = new FileInputStream(rsaPrivateKey);
        byte[] encodedPrivateKey = new byte[privK.available()];
        privK.read(encodedPrivateKey);
        privK.close();

        // PKCS8 decodes the encoded RSA private key
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        PrivateKey privateKey = kf.generatePrivate(privSpec);


        /* more preparation to decipher */

        // get session key
        FileInputStream secret = new FileInputStream(cipheredSessionKey);
        byte secretKeyB[] = new byte[secret.available()];
        secret.read(secretKeyB);
        secret.close();

        // get request ciphered
        FileInputStream cipheredtext = new FileInputStream(cipheredRequest);
        byte cipherTextB[] = new byte[cipheredtext.available()];
        cipheredtext.read(cipherTextB);
        cipheredtext.close();

        // get iv
        FileInputStream iv = new FileInputStream(ivFile);
        byte ivB[] = new byte[iv.available()];
        iv.read(ivB);
        iv.close();


        /* decipher */

        Cipher RSAdecipher = Cipher.getInstance("RSA");

        // decipher session key
        RSAdecipher.init(Cipher.DECRYPT_MODE, privateKey);
        SecretKey sesKey = new SecretKeySpec(RSAdecipher.doFinal(secretKeyB), "AES");

        IvParameterSpec ivSpec = new IvParameterSpec(ivB);

        // decipher file with session key
        Cipher AESdecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        AESdecipher.init(Cipher.DECRYPT_MODE, sesKey, ivSpec);

        byte[] requestDeciphered = AESdecipher.doFinal(cipherTextB);


        /* decode */

        byte[] decodedValue = Base64.getDecoder().decode(requestDeciphered);
        String requestClearText = new String(decodedValue, StandardCharsets.UTF_8);


        return requestClearText;
    }


    /**
     * METHOD printRequest - print the request deciphered and decoded
     * (so the author then decides if he wants to make a license)
     * @param request Request (string) already deciphered and decoded
     */
    private static void printRequest(String request)
    {
        System.out.println(request);
    }


    /**
     * METHOD makeLicense - if author accepted the request, the license is made
     * each piece of info is digest (except validity) and added to the license file
     * @param request Request (string) already deciphered and decoded
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws UnrecoverableKeyException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    private static void makeLicense(String request) throws KeyStoreException,
            CertificateException, NoSuchAlgorithmException, IOException,
            UnrecoverableKeyException, InvalidKeyException, SignatureException
    {
        /* set validity */

        Scanner sc = new Scanner(System.in);
        int daysValidity = -1;

        // validity in days
        do {
            System.out.print("Validity (in days): ");
            daysValidity = sc.nextInt();
        } while (daysValidity <= 0);

        // get validity's expiration date
        SimpleDateFormat date = new SimpleDateFormat("dd/MM/yyy");
        Calendar cal = Calendar.getInstance();
        cal.setTime(new Date());
        cal.add(Calendar.DATE, daysValidity);
        String validity = date.format(cal.getTime());
        System.out.println("( " + validity + " )");


        /* join with info from request and digest */

        String[] infoArray = request.split("\n");
        MessageDigest md = null;
        byte[] hash = null;
        StringBuilder sb = new StringBuilder();

        // digest each line (each piece of info)
        for (String line: infoArray)
        {
            // generate hash
            md = MessageDigest.getInstance("SHA-512");
            hash = md.digest(line.getBytes("UTF-8"));

            // convert to hex string
            for (int i = 0; i < hash.length; i++)
            {
                sb.append(Integer.toString((hash[i] & 0xff) + 0x100, 16).substring(1));
            }

            sb.append("\n");
        }


        /* save and sign */

        // append validity without digest
        sb.append(validity);

        // name of license file based on time (so names don't repeat)
        Date now = new Date();
        String format = new SimpleDateFormat("yyyyMMddHHmmss").format(now);
        String licenseName = path_licenses + "/license" + format;

        // save in file
        File license = new File(licenseName);
        PrintWriter output = new PrintWriter(license);
        output.write(sb.toString());
        output.close();

        // sign it
        signLicense(license);


        /* set permissions */

        // license file: read&write to the author, read only to everyone else
        Runtime.getRuntime().exec("chmod 644 " + license);

        // file containing the author's cc cert: read&write to the author, read only to everyone else
        File certFile = new File(ccAuthorCert);
        Runtime.getRuntime().exec("chmod 644 " + certFile);

        // file containing the author's signature: read&write to the author, read only to everyone else
        File sigFile = new File(authorSignature);
        Runtime.getRuntime().exec("chmod 644 " + sigFile);


        /* end */

        System.out.println("\nSend the license file to the user.");
    }


    /**
     * METHOD signLicense - signs digest license
     * @param license License file (with information digest already)
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws UnrecoverableKeyException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    private static void signLicense (File license) throws KeyStoreException,
            CertificateException, NoSuchAlgorithmException, IOException,
            UnrecoverableKeyException, InvalidKeyException, SignatureException
    {
        // get license file
        FileInputStream fis = new FileInputStream(license);
        byte inputb[] = new byte[fis.available()];
        fis.read(inputb);


        /* preparing CC */

        // configurations
        String pkcs11Config = "name=CartaoCidadao library=/usr/local/lib/libpteidpkcs11.so";
        byte [] pkcs11ConfigBytes = pkcs11Config.getBytes();
        ByteArrayInputStream pkcs11ConfigStream = new ByteArrayInputStream(pkcs11ConfigBytes);

        // provider
        Provider pkcs11Provider = new sun.security.pkcs11.SunPKCS11(pkcs11ConfigStream);
        Security.addProvider(pkcs11Provider);

        // key store
        KeyStore ks = KeyStore.getInstance("PKCS11");
        ks.load(null, null);

        String assinaturaCertLabel = "CITIZEN SIGNATURE CERTIFICATE";


        /* get things */

        // get certificate
        Certificate cert = ks.getCertificate(assinaturaCertLabel);
        byte[] certEnc = cert.getEncoded();

        // get CC's private key
        PrivateKey privkey = (PrivateKey) ks.getKey(assinaturaCertLabel, "author".toCharArray());


        /* sign */

        // initialize signature with the CC author private key
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign((PrivateKey) privkey);

        // supply signature with data to be signed
        BufferedInputStream bufin = new BufferedInputStream(fis);
        byte[] buffer = new byte[1024];
        int len;
        while ((len = bufin.read(buffer)) >= 0)
        {
            signature.update(buffer, 0, len);
        }

        fis.close();
        bufin.close();

        // generate signature
        byte[] sigB = signature.sign();


        /* save things */

        // save CC author certificate
        FileOutputStream authorcert = new FileOutputStream(ccAuthorCert);
        authorcert.write(certEnc);
        authorcert.close();

        // save the signature in a file
        FileOutputStream authorsig = new FileOutputStream(authorSignature);
        authorsig.write(sigB);
        authorsig.close();
    }
}
