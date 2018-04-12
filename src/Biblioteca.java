/**
 * Execution control Library
 * - constructor (appName, appVersion)
 * - methods:
 * -- createPaths(): void
 * -- isRegistered(): boolean
 * -- gatherInfo(): void
 * -- startRegistration(): boolean
 * -- cipherRequest(File tmpFile): void
 * -- signRequest(): void
 * -- validateSignature(): boolean
 * -- isReallyUser(): boolean
 * -- isValid(): boolean
 * -- showLicenseInfo(): void
 * Notes about files:
 * - the files' permissions is not checked, because the author
 * is responsible for giving the files with the right permissions.
 * - the files' existence is not checked;
 * - if a file doesn't exits (or anything else goes wrong),
 * the app execution ends and the user is told to contact authors;
 * - the user is responsible for keeping the files in the right place.
 */

import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.io.*;
import java.security.*;
import java.util.regex.Pattern;
import javax.crypto.*;
import javax.crypto.spec.*;


public class Biblioteca
{
    private Scanner sc;
    private StringBuilder sbReg;
    private FileOutputStream writeFileReg64;

    // about user
    private String name;
    private String mail;
    // about computer
    private String diskSerialNum;
    private String ramSize;
    private String linuxDistro;
    // about app
    private String appName;
    private String appVersion;


    /* paths needed */

    private String origin = System.getProperty("user.home");
    private String path_app =  origin + "/appHighNLow";
    private String path_requests = path_app + "/requests";
    private String path_licenses = path_app + "/licenses";
    private String path_keys = path_app + "/.keys";
    private String path_cc = path_app + "/.cc";

    private String appMainFile = path_app + "/AltoBaixo.java";

    private String rsaPublicKey = path_keys + "/publicKey";
    private String cipheredRequest = path_requests + "/cipheredRequest";
    private String ivFile = path_keys + "/IV";
    private String cipheredSessionKey = path_keys + "/cipheredSessionKey";

    private String userSignature = path_cc + "/userSignature";
    private String ccUserCert = path_cc + "/ccUserCert";

    private String licenseD;
    private String authorSignature = path_cc + "/authorSignature";
    private String ccAuthorCert = path_cc + "/ccAuthorCert";


    /* ------------------ */


    /**
     * CONSTRUCTOR - initializes the Library
     * instead of the method " void init (String nomeDaApp, String versao) "
     * also creates needed paths
     * @param nomeDaApp Application's name
     * @param versao Application's version
     */
    Biblioteca (String nomeDaApp, String versao)
    {
        appName = nomeDaApp;
        appVersion = versao;

        createPaths();
    }


    /**
     * METHOD createPaths - create all paths (if non-existent)
     */
    private void createPaths()
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
     * METHOD isRegistered - checks if user is registered
     * checks if there is a license file in the licenses directory
     * @return true if license file is found
     */
    protected boolean isRegistered()
    {
        File dir_licenses = new File (path_licenses);
        Pattern p = Pattern.compile("license[0-9]*");   // license files have a number in front of the name
        ArrayList<File> filesMatch = new ArrayList<>();
        String pathPart1 = path_licenses + "/";

        if(dir_licenses.isDirectory())
        {
            File[] files = dir_licenses.listFiles();

            for (File f: files)
            {
                if ( p.matcher(f.getName()).matches() )
                    filesMatch.add(new File(path_licenses + "/" + f.getName()));
            }

            // if no file matches
            if (filesMatch.size() == 0)
                return false;

            // if only exists one file that matches, choose that one
            else if (filesMatch.size() == 1)
                licenseD = pathPart1 + filesMatch.get(0).getName();

            // if more than one matches, choose the newest
            else
            {
                // sort the array list of files that match
                Collections.sort(filesMatch);
                // the most recent is the one that's on last place
                licenseD = pathPart1 + filesMatch.get(filesMatch.size()-1).getName();
            }

            return true;
        }

        else
            return false;
    }


    /**
     * METHOD gatherInfo - gathers all info from user, computer and app
     * appends everything to the StringBuilder sbReg
     * @throws IOException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws InterruptedException
     */
    private void gatherInfo() throws IOException, KeyStoreException,
            CertificateException, NoSuchAlgorithmException, InterruptedException
    {
        sbReg = new StringBuilder();
        sc = new Scanner(System.in);

        boolean validEmail = false;
        String EMAIL_REGEX = "^(\\w+)(.+)(\\w+)@(\\w+)(\\.)(\\w+)$";

        String line, line2 = "";
        String[] part;


        /* get name from CC */

        // preparing CC
        String pkcs11Config = "name=CartaoCidadao" + " library=/usr/local/lib/libpteidpkcs11.so";
        byte[] pkcs11ConfigBytes = pkcs11Config.getBytes();
        ByteArrayInputStream pkcs11ConfigStream = new ByteArrayInputStream(pkcs11ConfigBytes);

        // provider
        Provider pkcs11Provider = new sun.security.pkcs11.SunPKCS11(pkcs11ConfigStream);
        Security.addProvider(pkcs11Provider);

        // key store
        KeyStore ks = KeyStore.getInstance("PKCS11");
        ks.load(null, null);

        // get user's name from CC
        Certificate cert = (Certificate) ks.getCertificate("CITIZEN AUTHENTICATION CERTIFICATE");
        X509Certificate xc = (X509Certificate) cert;
        String all = xc.getSubjectDN().getName();
        String[] array_all = all.split(",");
        name = array_all[0].substring(3);

        sbReg.append(name).append("\n");


        /* get user email */

        do {
            System.out.print("Email: ");
            mail = sc.nextLine();

            if (mail.matches(EMAIL_REGEX))
            {
                sbReg.append(mail).append("\n");
                validEmail = true;
            }
        } while (validEmail == false);


        /* get pc info */

        // DISK: lsblk -nodeps -o name,serial

        // command
        String[] cmdDisk = {"lsblk", "-nodeps", "-o", "name,serial"};

        // run bash command
        Process pDisk = Runtime.getRuntime().exec(cmdDisk);
        pDisk.waitFor();

        // convert output to string
        BufferedReader inDisk = new BufferedReader(new InputStreamReader(pDisk.getInputStream()));
        line = inDisk.readLine();
        inDisk.close();

        // save part that matters in string
        part = line.split("sda");
        diskSerialNum = part[1].replaceAll("\\s", "");
        sbReg.append(diskSerialNum).append("\n");


        // RAM: cat /proc/meminfo

        // command
        String[] cmdRam = {"cat", "/proc/meminfo"};

        // run bash command
        Process pRam = Runtime.getRuntime().exec(cmdRam);
        pRam.waitFor();

        // convert output to string
        BufferedReader inRam = new BufferedReader(new InputStreamReader(pRam.getInputStream()));

        while ((line = inRam.readLine()) != null) {
            if (line.toLowerCase().contains("memtotal"))
                line2 = line;
        }

        inRam.close();

        // save part that matters in string
        part = line2.toLowerCase().split("memtotal:");
        ramSize = part[1].replaceAll("\\s", "");
        sbReg.append(ramSize).append("\n");


        // DISTRO: lsb_release -a | grep -i description

        // command
        String[] cmdDistro = {"lsb_release", "-a"};

        // run bash command
        Process pDistro = Runtime.getRuntime().exec(cmdDistro);
        pDistro.waitFor();

        // convert output to string
        BufferedReader inDistro = new BufferedReader(new InputStreamReader(pDistro.getInputStream()));

        while ((line = inDistro.readLine()) != null) {
            if (line.toLowerCase().contains("description"))
                line2 = line;
        }

        inDistro.close();

        // save part that matters in string
        part = line2.toLowerCase().split("description:");
        linuxDistro = part[1].replaceAll("\\s", "");
        sbReg.append(linuxDistro).append("\n");


        /* get app info */

        appName = AltoBaixo.NAME;
        appVersion = AltoBaixo.VERSION;
        sbReg.append(appName).append(" ").append(appVersion).append("\n");

        // digest the main file
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        FileInputStream fis = new FileInputStream(appMainFile);
        byte file[] = new byte[fis.available()];
        fis.read(file);

        byte[] dataBytes = new byte[1024];

        int nread = 0;
        while ((nread = fis.read(dataBytes)) != -1)
        {
            md.update(dataBytes, 0, nread);
        }
        byte[] mdbytes = md.digest();

        //convert the byte to hex format method 1
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < mdbytes.length; i++) {
            sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
        }

        sbReg.append(sb.toString());
        fis.close();
    }


    /**
     * METHOD starRegistration - process of registration of new license
     * if user does not agree with registration, the program will end
     * if user registers, the program will continue
     * all info is gathered into file encoded in base64
     * @return true if successful registration
     * @throws IOException
     * @throws InterruptedException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     * @throws SignatureException
     * @throws InvalidKeySpecException
     */
    protected boolean startRegistration() throws IOException, InterruptedException,
            IllegalBlockSizeException, InvalidKeyException, BadPaddingException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException,
            KeyStoreException, CertificateException, UnrecoverableKeyException,
            SignatureException, InvalidKeySpecException
    {
        /* gives opportunity to register */

        sc = new Scanner(System.in);

        System.out.println("This app is not registred.");
        System.out.print("Wish to get license? (y/N) ");
        String answer = sc.nextLine();

        if (answer.equals("y"))
        {
            /* get info */

            gatherInfo();


            /* write in files */

            // file that will contains the information encoded in base64 <- temporary file
            File tmpReg64 = new File(path_requests + "/regBase64");
            tmpReg64.createNewFile();
            writeFileReg64 = new FileOutputStream(tmpReg64);

            // get all info together
            String regData = sbReg.toString();

            // encode all data in base 64
            byte[] encodedBytes = Base64.getEncoder().encode(regData.getBytes("utf-8"));
            writeFileReg64.write(encodedBytes);


            /* cipher temporary file (encoded in base64) */

            cipherRequest(tmpReg64);


            /* close scanners and writers */

            sc.close();
            writeFileReg64.close();


            /* delete temporary file */

            tmpReg64.delete();


            /* all good */

            return true;
        }

        return false;
    }


    /**
     * METHOD cipherRequest - takes the registration file encoded in base64 and ciphers
     * @param tmpFile Temporary file with information encoded in base64
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeySpecException
     */
    private void cipherRequest(File tmpFile) throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException
    {
        /* get RSA 1024 public key */

        // open file
        File f = new File(rsaPublicKey);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int)f.length()];
        dis.readFully(keyBytes);
        dis.close();

        // encode to get object PublicKey
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pubKey = kf.generatePublic(spec);


        /* generate AES key */

        KeyGenerator AESKeyGenerator = KeyGenerator.getInstance("AES");
        AESKeyGenerator.init(128);

        // create a key
        SecretKey AES = AESKeyGenerator.generateKey();
        // get the raw key bytes
        byte[] simetrickey = AES.getEncoded();     // Returns copy of the key bytes


        /* cipher file */

        // IV
        byte [] iv = new byte[16];
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // create cipher based upon AES, cipher the message with AES key
        Cipher AEScipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        AEScipher.init(Cipher.ENCRYPT_MODE, AES, ivSpec);

        // initialize cipher with secret key AES
        FileInputStream file = new FileInputStream(tmpFile);
        byte inputb[] = new byte[file.available()];
        file.read(inputb);
        file.close();

        // cipher
        byte[] encrypted = AEScipher.doFinal(inputb);

        // save ciphered request
        File textoenc = new File(cipheredRequest);
        FileOutputStream fout = new FileOutputStream(textoenc);
        fout.write(encrypted);
        fout.close();


        /* sign */

        try {
            signRequest(textoenc);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }


        /* cipher session key (to send) */

        Cipher RSAcipher = Cipher.getInstance("RSA");
        RSAcipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] cryptedAES  = RSAcipher.doFinal(AES.getEncoded());

        // save iv
        FileOutputStream IV = new FileOutputStream(ivFile);
        IV.write(ivSpec.getIV());
        IV.close();

        // save ciphered session key
        FileOutputStream secretkey = new FileOutputStream(cipheredSessionKey);
        secretkey.write(cryptedAES);
        secretkey.close();


        /* set permissions */

        // ciphered request file: read&write to this user, read only to everyone else
        Runtime.getRuntime().exec("chmod 644 " + textoenc);

        // ciphered session key file: read&write to this user, read only to everyone else
        File keyFile = new File(cipheredSessionKey);
        Runtime.getRuntime().exec("chmod 644 " + keyFile);

        // iv file: read&write to this user, read only to everyone else
        File ivF = new File(ivFile);
        Runtime.getRuntime().exec("chmod 644 " + ivF);
    }


    /**
     * METHOD signRequest - signs the request already encoded and ciphered
     * @param requestCiph Request already ciphered
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws UnrecoverableKeyException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public void signRequest (File requestCiph) throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException, UnrecoverableKeyException,
            InvalidKeyException, SignatureException
    {
        // get temporary file
        FileInputStream fis = new FileInputStream(requestCiph);
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
        PrivateKey privkey = (PrivateKey) ks.getKey(assinaturaCertLabel, "user".toCharArray());


        /* sign */

        // initialize signature with the CC user private key
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

        // save CC user certificate
        FileOutputStream usercert = new FileOutputStream(ccUserCert);
        usercert.write(certEnc);
        usercert.close();

        // save the signature in a file
        FileOutputStream usersig = new FileOutputStream(userSignature);
        usersig.write(sigB);
        usersig.close();
    }


    /**
     * METHOD validateSignature - verifies author signature
     * @return true is the author signature is valid
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws UnrecoverableKeyException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    protected boolean validateSignature() throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException, UnrecoverableKeyException,
            InvalidKeyException, SignatureException
    {
        /* read files */

        // read CC author cert file
        FileInputStream authorcert = new FileInputStream(ccAuthorCert);
        byte[] certB = new byte[authorcert.available()];
        authorcert.read(certB);
        authorcert.close();

        // read license file
        FileInputStream fis = new FileInputStream(licenseD);
        byte[] fileB = new byte[fis.available()];
        fis.read(fileB);

        // read signature file
        FileInputStream fsig = new FileInputStream(authorSignature);
        byte[] sigB = new byte[fsig.available()];
        fsig.read(sigB);
        fsig.close();


        /* CC things */

        // get certificate
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(certB);
        Certificate cert = (Certificate) certFactory.generateCertificate(in);

        // get CC author key
        PublicKey pubKeyAuthor = (PublicKey) cert.getPublicKey();


        /* verify signature */

        // verify signature with the CC author public key
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(pubKeyAuthor);

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
     * METHOD isReallyUser - gathers all info, makes digest of each piece of info and
     * compares those digest lines with the lines in the license
     * @return true if all checks out
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InterruptedException
     */
    protected boolean isReallyUser() throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException, InterruptedException
    {
        gatherInfo();


        /* digest this info */

        String[] infoArray = sbReg.toString().split("\n");
        MessageDigest md = null;
        byte[] hash = null;
        StringBuilder sb = new StringBuilder();

        // digest each piece of info
        for (String s : infoArray)
        {
            // generate hash
            md = MessageDigest.getInstance("SHA-512");
            hash = md.digest(s.getBytes("UTF-8"));

            // convert to hex string
            for (int i = 0; i < hash.length; i++) {
                sb.append(Integer.toString((hash[i] & 0xff) + 0x100, 16).substring(1));
            }

            sb.append("\n");
        }

        String[] digestArray = sb.toString().split("\n");
        ArrayList<String> infoDigest = new ArrayList<>();
        for (String s : digestArray)
            infoDigest.add(s);


        /* get digest license file */

        File f = new File(licenseD);
        Scanner scf = new Scanner(f);
        ArrayList<String> infoDigestFile = new ArrayList<>();

        while (scf.hasNextLine())
        {
            infoDigestFile.add(scf.nextLine());
        }
        scf.close();


        /* compare digested info gotten here with digest info from file */

        int nelem = 7;  // were collected 7 elements

        // if any (one or more) of the digest (each line is "digested") are not equal, then some changed
        for (int i = 0; i < nelem; i++) {
            if (!infoDigest.get(i).equals(infoDigestFile.get(i)))
                return false;
        }

        return true;
    }


    /**
     * METHOD isValid - checks if the license if still valid (expiration date)
     * @return true if validity hasn't expired
     * @throws FileNotFoundException
     * @throws ParseException
     */
    protected boolean isValid() throws FileNotFoundException, ParseException
    {
        /* get validity */

        File f = new File(licenseD);
        Scanner scf = new Scanner(f);
        String lastLine = null;

        // get last line of the license file
        while (scf.hasNextLine())
        {
            lastLine = scf.nextLine();
        }
        scf.close();

        // convert from string to date
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy");
        LocalDate endDate = LocalDate.parse(lastLine, formatter);


        /* get today's date */

        LocalDate today = LocalDate.now();


        /* check if it's still valid */

        if (today.isBefore(endDate) || today.isEqual(endDate))
            return true;


        return false;
    }


    /**
     * METHOD showLicenseInfo - shows all info present in license
     * @throws FileNotFoundException
     */
    protected void showLicenseInfo() throws FileNotFoundException
    {
        /*
        - if the author's signature is truthful
        - if the user is who he says -> i.e. after gathering all the info here with sbReg,
        digest each piece of info and compare it to the lines in the license
        (except the last one), if all is the same, then the user is who he says.
        - then, showing the info gathered in sbReg is the same that showing the license itself!
        - because we can't show the license by printing the lines in the license file
        (because each line is digest), each line of sbReg is printed.
        - and because the last line of the license file wasn't digest, is the only line
        that can be printed here (and it will)
         */
        System.out.println(sbReg.toString());


        /* get validity */

        File f = new File(licenseD);
        Scanner scf = new Scanner(f);
        String lastLine = null;

        // get last line of the license file
        while (scf.hasNextLine())
        {
            lastLine = scf.nextLine();
        }
        scf.close();

        System.out.println("Validity expires at: " + lastLine);
    }
}