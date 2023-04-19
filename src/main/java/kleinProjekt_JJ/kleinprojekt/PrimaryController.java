package kleinProjekt_JJ.kleinprojekt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.input.DragEvent;
import javafx.scene.input.Dragboard;
import javafx.scene.input.TransferMode;
import javafx.scene.layout.Pane;

public class PrimaryController {
	private static final String PASSWORD_REGEX = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,20}$";

	 @FXML
	    private TextField tfDestination;

	    @FXML
	    private TextField tfPath;

	    @FXML
	    private PasswordField pfPass;

	    @FXML
	    private CheckBox cbPath;

	    @FXML
	    private Button btnEncrypt;

	    @FXML
	    private Button btnDecrypt;

	    @FXML
	    private Pane pDrop;
	    
	    @FXML
	    private Label lbSum1;

	    @FXML
	    private Label lbSum2;

	    

	    @FXML
	    void onDragDropped(DragEvent event) {
	    	Dragboard db = event.getDragboard();
	        boolean success = false;
	        if (db.hasFiles()) {
	            success = true;
	            File file = db.getFiles().get(0);
	            String path = file.getAbsolutePath();
	            tfPath.setText(path);
	        }
	        event.setDropCompleted(success);
	        event.consume();
	    }

	    @FXML
	    void onDragOver(DragEvent event) {
	    	if (event.getGestureSource() != pDrop) {
	            if (event.getDragboard().hasFiles()) {
	                event.acceptTransferModes(TransferMode.COPY);
	                event.consume();
	            }
	        }
	    }
	    
	    @FXML
	    void onDecrypt(ActionEvent event) throws Exception {
	    	String filePath = tfPath.getText();
	        String password = pfPass.getText();
	        File inputFile = new File(filePath);

	        // validate password and file path
	        if (!validatePass(password)) {
	            JOptionPane.showMessageDialog(null, "Invalid password. Please try again.");
	            return;
	        }

	        if (!inputFile.exists()) {
	            JOptionPane.showMessageDialog(null, "Invalid path. Please try again.");
	            return;
	        }
	        lbSum1.setVisible(true);
    	    lbSum1.setText("Before: " + checkSumm(filePath));

	        // perform decryption
	        try {
	            // read the input file
	            byte[] inputBytes = Files.readAllBytes(inputFile.toPath());

	            // split the input bytes into the initialization vector and encrypted data
	            byte[] iv = Arrays.copyOfRange(inputBytes, 0, 16);
	            byte[] encryptedBytes = Arrays.copyOfRange(inputBytes, 16, inputBytes.length);

	            // generate a secret key from the password
	            byte[] salt = new byte[16];
	            SecureRandom random = new SecureRandom();
	            random.nextBytes(salt);
	            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
	            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
	            SecretKey tmp = factory.generateSecret(spec);
	            SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

	            // initialize the cipher in decrypt mode
	            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

	            // decrypt the input bytes
	            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

	            // write the decrypted bytes to a file
	            String outputPath = cbPath.isSelected() ? tfPath.getText() : tfDestination.getText();
	            File outputFile = new File(outputPath);
	            FileOutputStream fos = new FileOutputStream(outputFile);
	            fos.write(decryptedBytes);
	            fos.close();
	            
	            lbSum2.setVisible(true);
	    	    lbSum2.setText("After: " + checkSumm(outputPath));

	            // display success message
	            JOptionPane.showMessageDialog(null, "File decrypted successfully.");
	        } catch (Exception e) {
	            e.printStackTrace();
	            JOptionPane.showMessageDialog(null, "Decryption failed. Please try again.");
	        }
	    		
	        k
	    }

	    @FXML
	    void onEncrypt(ActionEvent event) throws Exception {
	    	 String filePath = tfPath.getText();
	    	    String password = pfPass.getText();
	    	    File inputFile = new File(filePath);

	    	    // validate password and file path
	    	    if (!validatePass(password)) {
	    	        JOptionPane.showMessageDialog(null, "Invalid password. Please try again.");
	    	        return;
	    	    }

	    	    if (!inputFile.exists()) {
	    	        JOptionPane.showMessageDialog(null, "Invalid path. Please try again.");
	    	        return;
	    	    }
	    	    lbSum1.setVisible(true);
	    	    lbSum1.setText("Before: " + checkSumm(filePath));
	    	    // perform encryption
	    	    try {
	    	        // read the input file
	    	        byte[] inputBytes = Files.readAllBytes(inputFile.toPath());

	    	        // generate a salt and secret key from the password using PBKDF2 with HMAC SHA-256
	    	        byte[] salt = new byte[16];
	    	        SecureRandom random = new SecureRandom();
	    	        random.nextBytes(salt);

	    	        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
	    	        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
	    	        SecretKey tmp = factory.generateSecret(spec);
	    	        SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

	    	        // generate a random initialization vector
	    	        byte[] iv = new byte[16];
	    	        random.nextBytes(iv);

	    	        // initialize the cipher in encrypt mode
	    	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    	        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

	    	        // encrypt the input bytes
	    	        byte[] encryptedBytes = cipher.doFinal(inputBytes);

	    	        // write the salt, IV, and encrypted bytes to a file
	    	        String outputPath = cbPath.isSelected() ? tfPath.getText() : tfDestination.getText();
	    	        File outputFile = new File(outputPath);
	    	        FileOutputStream fos = new FileOutputStream(outputFile);
	    	        fos.write(salt);
	    	        fos.write(iv);
	    	        fos.write(encryptedBytes);
	    	        fos.close();
	    	        
	    	        lbSum2.setVisible(true);
	    	        lbSum2.setText("After: "+checkSumm(outputPath));
	    	        // display success message
	    	        JOptionPane.showMessageDialog(null, "File encrypted successfully.");
	    	    } catch (Exception e) {
	    	        e.printStackTrace();
	    	        JOptionPane.showMessageDialog(null, "Encryption failed. Please try again.");
	    	    }
	    }
	    
	    
	    

	    @FXML
	    void onCheckBox(ActionEvent event) {
	    	
	    	if(!cbPath.isSelected()) {
	    		tfDestination.setDisable(false);
	    		return;
	    	}
	    	
    		tfDestination.clear();
    		tfDestination.setDisable(true);
	    	
	    }
	    
	    public boolean validatePass(String pass) {

			Pattern pattern = Pattern.compile(PASSWORD_REGEX);
			Matcher matcher = pattern.matcher(pass);
			return matcher.matches();
	    
	    }
	    
	    String checkSumm(String path) throws Exception {
	    	
	    	MessageDigest digest = MessageDigest.getInstance("SHA-256");
    		FileInputStream fis = new FileInputStream(path);

    		byte[] dataBytes = new byte[1024];

    		int nread = 0;
    		while ((nread = fis.read(dataBytes)) != -1) {
    			digest.update(dataBytes, 0, nread);
    		}
    		fis.close();
    		byte[] mdbytes = digest.digest();

    		StringBuilder sb = new StringBuilder();
    		for (int i = 0; i < mdbytes.length; i++) {
    			sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
    		}
    		return sb.toString();
	    	
	    }
	    
	    
	    
}
