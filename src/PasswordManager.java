import java.util.*;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PasswordManager {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Do you want to generate passwords or crack passwords? (G/C)");
        String choice = scanner.nextLine().trim().toUpperCase();

        if (choice.equals("G")) {
            // Run password generation code
            generatePasswords(scanner);
        } else if (choice.equals("C")) {
            // Run password cracking code
            crackPasswords(scanner);
        } else {
            System.out.println("Invalid choice. Please enter 'G' to generate or 'C' to crack passwords.");
        }

        scanner.close();
    }

    public static void generatePasswords(Scanner scanner) throws IOException, NoSuchAlgorithmException {

        System.out.print("Enter minimum password length: ");
        int minLength = scanner.nextInt();

        System.out.print("Enter maximum password length: ");
        int maxLength = scanner.nextInt();

        System.out.print("Enter number of accounts: ");
        int numAccounts = scanner.nextInt();

        scanner.nextLine(); // Consume leftover newline


        PrintWriter file1 = new PrintWriter(new FileWriter("passwordfile1.txt"));
        PrintWriter file2 = new PrintWriter(new FileWriter("passwordfile2.txt"));
        PrintWriter file3 = new PrintWriter(new FileWriter("passwordfile3.txt"));

        String usernameSuffix = "aaa";

        for (int i = 0; i < numAccounts; i++) {
            String username = "usr" + usernameSuffix;


            String password1 = generateRandomPassword(minLength, maxLength);
            String password2 = generateRandomPassword(minLength, maxLength);
            String password3 = generateRandomPassword(minLength, maxLength);

            file1.println(username + ":" + password1);

            String hashedPassword2 = hashPassword(password2);
            file2.println(username + ":" + hashedPassword2);

            String salt = generateRandomSalt();
            String hashedPassword3 = hashPasswordWithSalt(password3, salt);
            file3.println(username + ":" + salt + ":" + hashedPassword3);


            usernameSuffix = incrementString(usernameSuffix);
        }

        file1.close();
        file2.close();
        file3.close();

        System.out.println("Password files generated successfully.");
    }

    public static void crackPasswords(Scanner scanner) throws IOException, NoSuchAlgorithmException {
        System.out.print("Enter the password file to crack: ");
        String passwordFile = scanner.nextLine();

        File file = new File(passwordFile);
        while (!file.exists()) {
            System.out.println("File not found. Please enter a valid password file name:");
            passwordFile = scanner.nextLine();
            file = new File(passwordFile);
        }

        System.out.print("Enter maximum password length to attempt: ");
        int maxPasswordLength = scanner.nextInt();

        scanner.nextLine();

        int fileType = getPasswordFileType(passwordFile);

        if (fileType == 1) {
            crackType1PasswordFile(passwordFile);
        } else if (fileType == 2) {
            crackType2PasswordFile(passwordFile, maxPasswordLength);
        } else if (fileType == 3) {
            crackType3PasswordFile(passwordFile, maxPasswordLength);
        } else {
            System.out.println("Unsupported password file type or incorrect file format.");
        }
    }
    public static String incrementString(String str) {
        char[] chars = str.toCharArray();
        int index = chars.length - 1;
        while (index >= 0) {
            if (chars[index] == 'z') {
                chars[index] = 'a';
                index--;
            } else {
                chars[index]++;
                break;
            }
        }
        return new String(chars);
    }

    public static String generateRandomPassword(int minLength, int maxLength) {
        Random rnd = new Random();
        int length = minLength + rnd.nextInt(maxLength - minLength + 1);
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder password = new StringBuilder();
        for (int i = 0; i < length; i++) {
            password.append(chars.charAt(rnd.nextInt(chars.length())));
        }
        return password.toString();
    }

    public static String generateRandomSalt() {
        Random rnd = new Random();
        byte[] saltBytes = new byte[16]; // 16 bytes salt
        rnd.nextBytes(saltBytes);
        return bytesToHex(saltBytes);
    }

    public static int getPasswordFileType(String passwordFile) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(passwordFile));
        String line = br.readLine();
        br.close();

        if (line == null) {
            return -1;
        }

        String[] parts = line.split(":");
        if (parts.length == 2) {
            if (isProbablyHashed(parts[1])) {
                return 2;
            } else {
                return 1;
            }
        } else if (parts.length == 3) {
            return 3;
        } else {
            return -1;
        }
    }

    public static boolean isProbablyHashed(String password) {
        return password.matches("[0-9a-fA-F]{64}");
    }

    public static void crackType1PasswordFile(String passwordFile) throws IOException {
        System.out.println("Passwords in Type 1 password file are stored in plaintext:");
        BufferedReader br = new BufferedReader(new FileReader(passwordFile));
        String line;
        while ((line = br.readLine()) != null) {
            System.out.println(line);
        }
        br.close();
    }

    public static void crackType2PasswordFile(String passwordFile, int maxPasswordLength)
            throws IOException, NoSuchAlgorithmException {
        Map<String, String> userHashes = new HashMap<>();

        BufferedReader br = new BufferedReader(new FileReader(passwordFile));
        String line;
        while ((line = br.readLine()) != null) {
            String[] parts = line.split(":");
            String username = parts[0];
            String hashedPassword = parts[1];
            userHashes.put(hashedPassword, username);
        }
        br.close();

        System.out.println("Attempting to crack passwords from Type 2 password file...");
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        for (int length = 1; length <= maxPasswordLength; length++) {
            System.out.println("Trying passwords of length " + length + "...");
            crackPasswordsRecursive("", chars, length, userHashes, false);
            if (userHashes.isEmpty()) {
                break;
            }
        }

        if (!userHashes.isEmpty()) {
            System.out.println("Not all passwords were cracked.");
        }
    }

    public static void crackType3PasswordFile(String passwordFile, int maxPasswordLength)
            throws IOException, NoSuchAlgorithmException {
        List<UserSaltHash> userSaltHashes = new ArrayList<>();


        BufferedReader br = new BufferedReader(new FileReader(passwordFile));
        String line;
        while ((line = br.readLine()) != null) {
            String[] parts = line.split(":");
            userSaltHashes.add(new UserSaltHash(parts[0], parts[1], parts[2]));
        }
        br.close();

        System.out.println("Attempting to crack passwords from Type 3 password file...");
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        for (int length = 1; length <= maxPasswordLength; length++) {
            System.out.println("Trying passwords of length " + length + "...");
            crackPasswordsRecursive("", chars, length, userSaltHashes);
            if (userSaltHashes.isEmpty()) {
                break;
            }
        }

        if (!userSaltHashes.isEmpty()) {
            System.out.println("Not all passwords were cracked.");
        }
    }

    public static void crackPasswordsRecursive(String prefix, String chars, int maxLength,
                                               Map<String, String> userHashes, boolean isType3)
            throws NoSuchAlgorithmException {
        if (prefix.length() == maxLength) {
            String hashedAttempt = hashPassword(prefix);
            if (userHashes.containsKey(hashedAttempt)) {
                String username = userHashes.get(hashedAttempt);
                System.out.println("Password found!");
                System.out.println("Username: " + username);
                System.out.println("Password: " + prefix);
                userHashes.remove(hashedAttempt);
            }
            return;
        }
        for (int i = 0; i < chars.length(); i++) {
            crackPasswordsRecursive(prefix + chars.charAt(i), chars, maxLength, userHashes, isType3);
            if (userHashes.isEmpty()) {
                return;
            }
        }
    }

    public static void crackPasswordsRecursive(String prefix, String chars, int maxLength,
                                               List<UserSaltHash> userSaltHashes)
            throws NoSuchAlgorithmException {
        if (prefix.length() == maxLength) {
            Iterator<UserSaltHash> iterator = userSaltHashes.iterator();
            while (iterator.hasNext()) {
                UserSaltHash ush = iterator.next();
                String hashedAttempt = hashPasswordWithSalt(prefix, ush.salt);
                if (hashedAttempt.equals(ush.hashedPassword)) {
                    System.out.println("Password found!");
                    System.out.println("Username: " + ush.username);
                    System.out.println("Password: " + prefix);
                    iterator.remove();
                }
            }
            return;
        }
        for (int i = 0; i < chars.length(); i++) {
            crackPasswordsRecursive(prefix + chars.charAt(i), chars, maxLength, userSaltHashes);
            if (userSaltHashes.isEmpty()) {
                return;
            }
        }
    }

    public static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(password.getBytes());
        return bytesToHex(hashBytes);
    }

    public static String hashPasswordWithSalt(String password, String salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt.getBytes());
        byte[] hashBytes = md.digest(password.getBytes());
        return bytesToHex(hashBytes);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    static class UserSaltHash {
        String username;
        String salt;
        String hashedPassword;

        public UserSaltHash(String username, String salt, String hashedPassword) {
            this.username = username;
            this.salt = salt;
            this.hashedPassword = hashedPassword;
        }
    }
}