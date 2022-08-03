package il.ac.kinneret.mjmay.hls.hlsjava.model;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.stream.Stream;

/**
 * Class to perform encryption and decryption operations of messages and files
 * @authors Sasha Chernin & Hai Palatshi
 */
public class Encryption {

    public static SecretKey secretKey;
    public static SecretKey macKey;
    public static String myName;
    public static PrivateKey privateKey;
    public static HashMap<String, String> publicKeys = new HashMap<String, String>();
    public static final int GCM_TAG_LENGTH = 16;

    static {
        try {
            secretKey = retrieveSecretKey();
            macKey = retrieveMACKey();
            myName = retrieveName();
            privateKey = retrievePrivateKey();
            buildKeysMap();
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    /**
     * Retrieves password from config file and transforms it into a sha256 digest to use as a key
     * @return SecretKeySpec object that is initialized with the sha256 version of the password
     */
    public static SecretKey retrieveSecretKey() throws NoSuchAlgorithmException, IOException {
        FileReader file = new FileReader("Config");
        BufferedReader buffer = new BufferedReader(file);
        //read the 1st line
        String keyText = buffer.readLine();

        // String to bytes array
        byte[] arr = keyText.getBytes(StandardCharsets.UTF_8);
        // bytes array to sha-256 hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return new SecretKeySpec(digest.digest(arr), 0, digest.digest(arr).length, "AES");
    }

    /**
     * Retrieves MAC password from config file and transforms it into a sha256 digest to use as a key
     * @return SecretKeySpec object that is initialized with the sha256 version of the password
     */
    public static SecretKey retrieveMACKey() throws NoSuchAlgorithmException, IOException {
        //read the 2nd line
        String macText = Files.readAllLines(Paths.get("Config")).get(1);

        // String to bytes array
        byte[] arr = macText.getBytes(StandardCharsets.UTF_8);
        // bytes array to sha-256 hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return new SecretKeySpec(digest.digest(arr), 0, digest.digest(arr).length, "AES");
    }

    /**
     * Encrypts string in AES-CBC mode
     * @param value The string that is being encrypted
     * @return The encrypted string
     */
    public static String encryptMessage(String value) {
        try {

            // append time, name and digitally sign
            String message = appendTimeNameSignature(value);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

            // generate iv
            SecureRandom randomSecureRandom = new SecureRandom();
            byte[] iv = new byte[cipher.getBlockSize()];
            randomSecureRandom.nextBytes(iv);
            IvParameterSpec ivParams = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);

            // preform encryption in the message
            byte[] encrypted = cipher.doFinal(message.getBytes());

            // create output stream that will contain iv + enc data
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            // write iv to the first 16 bytes of output array
            output.write(ivParams.getIV());
            // write the encrypted message to the output array
            output.write(encrypted);

            // calc hmac
            byte[] macSignature = calcHMACSignature(output.toByteArray());


            // create new output that will contain mac signature, iv, enc data and write to it.
            ByteArrayOutputStream outputWithSignature = new ByteArrayOutputStream();
            outputWithSignature.write(macSignature);
            outputWithSignature.write(ivParams.getIV());
            outputWithSignature.write(encrypted);

            // convert output array to bytes array and return it
            byte[] out = outputWithSignature.toByteArray();

            return Base64.getEncoder().encodeToString(out);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypts string in AES-CBC mode and check MAC signature
     * @param encrypted The string that is being decrypted
     * @return The decrypted string
     */
    public static String decryptMessage(String encrypted) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidKeySpecException {

        byte[] StrToDecrypt = Base64.getDecoder().decode(encrypted);

        byte[] strToEnc = Arrays.copyOfRange(StrToDecrypt, 48, StrToDecrypt.length);

        // received string without mac
        byte[] checkMAC = Arrays.copyOfRange(StrToDecrypt, 32, StrToDecrypt.length);

        // received mac
        byte[] macSignature = Arrays.copyOfRange(StrToDecrypt, 0, 32);


        if (Arrays.equals(macSignature, calcHMACSignature(checkMAC))) {
            // just continue
        }
        else {
            return "WRONGMAC";
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKey,
                new IvParameterSpec(StrToDecrypt, 32, 16));

        byte[] original = cipher.doFinal(strToEnc);

        String decrypted = new String(original);
        // check delay
        int delay = getTimeDelay(decrypted);
        if (delay>5000) {
            LoggerFile.getInstance().info("Timestamp check failed");
            return "BigDelay";
        }
        else if (verifySignature(decrypted)) {
            LoggerFile.getInstance().info("Timestamp check was successful");
            LoggerFile.getInstance().info("Signature verification was successful");
            return originalMessage(decrypted);
        }
        else {
            LoggerFile.getInstance().info("Timestamp check was successful");
            LoggerFile.getInstance().info("Signature verification failed");
            return "BadSignature";
        }

    }

    /**
     * Encrypts file in AES-CTR mode
     * @param originalFile The full path of the file including the file name
     * @param fileName The full path of the target file including the file name
     */
    public static void encryptFile(String originalFile ,String fileName) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, InvalidAlgorithmParameterException, SignatureException {

        addTimeNameSignatureToFile(originalFile);

        String copiedName = originalFile.replaceFirst("(\\.[^\\.]*)?$", "-copy$0");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // generate iv
        SecureRandom randomSecureRandom = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        randomSecureRandom.nextBytes(iv);
        IvParameterSpec ivParams = new IvParameterSpec(iv);

        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, ivParams.getIV());

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] array = Files.readAllBytes(Paths.get(copiedName));

        try (FileOutputStream fileOut = new FileOutputStream(fileName);
             CipherOutputStream cipherOut = new CipherOutputStream(fileOut, cipher)) {
            fileOut.write(gcmParameterSpec.getIV());
            cipherOut.write(array);

            cipherOut.flush();
            cipherOut.close();
            fileOut.flush();
            fileOut.close();

        }
    }

    /**
     * Decrypts file in AES-CTR mode
     *
     * @param fileName The full path of the file including the file name
     * @param decName  The full path of the target file including the file name
     * @return
     */
    public static String decryptFile(String fileName, String decName) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, InvalidKeyException {
        byte[] array = Files.readAllBytes(Paths.get(fileName));
        byte[] withoutIV = Arrays.copyOfRange(array, 16, array.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        try (FileInputStream fileIn = new FileInputStream(fileName)) {
            byte[] fileIv = new byte[16];
            fileIn.read(fileIv);

            // Create GCMParameterSpec
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, fileIv);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);


            try (FileOutputStream fileOut = new FileOutputStream(decName);
                 CipherOutputStream cipherOut = new CipherOutputStream(fileOut, cipher)) {
                cipherOut.write(withoutIV);

                cipherOut.flush();
                cipherOut.close();
                fileOut.flush();
                fileOut.close();
            }

        } catch (IOException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
        }


        String nameTimeSig = getAppendedContentFromFile(decName);

        if (getTimeDelay(nameTimeSig)>5000) {
            LoggerFile.getInstance().info("Timestamp check failed");
            // delete downloaded file
            File myObj = new File(decName);
            myObj.delete();
            File myObj2 = new File(fileName);
            myObj2.delete();
            return "BigDelay";
        }
        else if (verifySignatureFile(decName, nameTimeSig))
        {
            LoggerFile.getInstance().info("Timestamp check was successful");
            LoggerFile.getInstance().info("Signature check failed");
            File myObj = new File(decName);
            myObj.delete();
            File myObj2 = new File(fileName);
            myObj2.delete();
            return "FailedSignature";
        }
        else
        {
            LoggerFile.getInstance().info("Timestamp check was successful");
            LoggerFile.getInstance().info("Signature check was successful");
            return "0";
        }
    }

    /**
     * Calculates MAC digest from a given bytes array
     * @param data The bytes array that should contain iv+encrypted message
     */
    public static byte[] calcHMACSignature(byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKey);
        return mac.doFinal(data);
    }

    /**
     * Transforms bytes array to hex. returns string.
     * @param bytes The bytes array that is being transformed.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte hashByte : bytes) {
            int intVal = 0xff & hashByte;
            if (intVal < 0x10) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(intVal));
        }
        return sb.toString();
    }

    /**
     * Retrieves nodes name from config file
     * @return string object which is the name of the node
     */
    public static String retrieveName() throws NoSuchAlgorithmException, IOException {
        FileReader file = new FileReader("config");
        BufferedReader buffer = new BufferedReader(file);
        //read the 3rd line
        String myName = Files.readAllLines(Paths.get("config")).get(2);

        return myName;
    }


    public static PrivateKey retrievePrivateKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        FileReader file = new FileReader("Config");
        BufferedReader buffer = new BufferedReader(file);
        //read the 4th line
        String strKey = Files.readAllLines(Paths.get("Config")).get(3);

        byte[] keyBytes = Base64.getDecoder().decode(strKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        return privateKey;
    }

    public static void buildKeysMap() throws IOException {
        Stream<String> readFileStream = null;
        readFileStream = Files.lines(Paths.get("public"));

        readFileStream.forEach( line -> {
            String[] key = line.split(":");
            publicKeys.put(key[0], (key[1]));
        });
    }

    public static String appendTimeNameSignature(String message) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        message=message.concat(" "+myName+" "+getISO8601Timestamp());

        String signed = message.concat(" "+createDigitalSignature(message));
        return signed;
    }


    /** GetISO8601 Format Time from current time
     *
     * @return current ISO8601 time as String
     * @throws Exception
     */
    public static String getISO8601Timestamp()
    {

        //TimeZone tz = TimeZone.getTimeZone("UTC");
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss"); // Quoted "Z" to indicate UTC, no timezone offset
        //df.setTimeZone(tz);
        String nowAsISO = df.format(new Date());
        return nowAsISO;

    }

    // create digital sig
    public static String createDigitalSignature(String message) throws NoSuchAlgorithmException,SignatureException,InvalidKeyException
    {

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        byte[] bytes = message.getBytes();

        sig.update(bytes);
        return bytesToHex(sig.sign());
    }

    public static int getTimeDelay(String message) throws IOException {
        String[] splitMessage = message.split(" ");
        String time = splitMessage[splitMessage.length-2];
        LoggerFile.getInstance().info("Received timestamp: "+time);

        try {

            DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

            Date result1 = df.parse(time);

            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MMM-dd'T'HH:mm:ss");

            SimpleDateFormat ldf = new SimpleDateFormat("yyyy-MMM-dd'T'HH:mm:ss");


            Date d1 = ldf.parse(sdf.format(new Date()));

            return (int) (d1.getTime() - result1.getTime());
        }
        catch(ParseException e)
        {
            e.printStackTrace();
        }

        return 0;
    }

    public static boolean verifySignature(String message) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, IOException {
        String[] splitMessage = message.split(" ");
        String name = splitMessage[splitMessage.length-3];
        LoggerFile.getInstance().info("Senders identity: "+name);

        String strSig = splitMessage[splitMessage.length-1];

        String withoutSig = message.substring(0, message.lastIndexOf(" "));

        byte[] signature =hexStringToByteArray(strSig);
        byte[] bytesMessage = withoutSig.getBytes();
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(getPublicKey(publicKeys.get(name)));
        sig.update(bytesMessage);
        return sig.verify(signature);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static PublicKey getPublicKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        return publicKey;
    }

    public static String originalMessage(String message)
    {
        String[] messageParts = message.split(" ");
        String sig = messageParts[messageParts.length - 1];
        String time = messageParts[messageParts.length - 2];
        String name = messageParts[messageParts.length - 3];
        String original = message.substring(0, message.indexOf(sig)).trim();
        original = message.substring(0, message.indexOf(name)).trim();

        return original;
    }

    public static String getAppendedContentFromFile(String filename) throws IOException {
        byte[] nameTimeSig = new byte[1046];
        File file = new File(filename);
        RandomAccessFile raf = new RandomAccessFile(file, "r");

        // Seek to the end of file
        raf.seek(file.length() - 1046);
        // Read it out.
        raf.read(nameTimeSig, 0, 1046);
        File tempFile = new File(filename);


        return new String(nameTimeSig, StandardCharsets.UTF_8);
    }

    public static boolean verifySignatureFile(String filename, String nameTimeSig) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, IOException {
        String signatureStr = nameTimeSig.split(" ")[2];
        String name = nameTimeSig.split(" ")[0];
        byte[] array = Files.readAllBytes(Paths.get(filename));
        byte[] withoutSig = Arrays.copyOfRange(array, 0, array.length-1024);

        byte[] signature =hexStringToByteArray(signatureStr);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(getPublicKey(publicKeys.get(myName)));
        sig.update(withoutSig);
        return sig.verify(signature);
    }

    public static void addTimeNameSignatureToFile(String originalFile) throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // create duplication of a file
        Path file = Paths.get(originalFile);
        String name = file.getFileName().toString();
        String copiedName = name.replaceFirst("(\\.[^\\.]*)?$", "-copy$0");
        Path copiedFile = file.resolveSibling(copiedName);
        Files.copy(file, copiedFile);


        String contentToAppend = myName+" "+getISO8601Timestamp()+" ";
        Files.write(
                copiedFile,
                contentToAppend.getBytes(),
                StandardOpenOption.APPEND);

        // sign file content and append
        byte[] array = Files.readAllBytes(copiedFile);
        contentToAppend = createDigitalSignatureFile(array);
        Files.write(
                copiedFile,
                contentToAppend.getBytes(),
                StandardOpenOption.APPEND);
    }

    public static String createDigitalSignatureFile(byte[] content) throws NoSuchAlgorithmException,SignatureException,InvalidKeyException
    {


        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(content);
        return bytesToHex(sig.sign());
    }

}
