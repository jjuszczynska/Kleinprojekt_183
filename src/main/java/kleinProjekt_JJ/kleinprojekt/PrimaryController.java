package kleinProjekt_JJ.kleinprojekt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
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
	    private Label lbChecksumm;
    

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
	    	String outputPath = cbPath.isSelected() ? tfPath.getText() : tfDestination.getText();

	    	// validate password and file path
	    	if (!validatePass(password)) {
	    	    JOptionPane.showMessageDialog(null, "Invalid password. Please try again.\nPassword must have at least one uppercase letter,\none lowercase letter, one digit,\nand one special character among @#$%^&+=, be 8-20 characters long, and contain no whitespace.");
	    	    
	    	    return;
	    	}

	    	if (!inputFile.exists()) {
	    	    JOptionPane.showMessageDialog(null, "Invalid path. Please try again.");
	    	    return;
	    	}
	    	
	    	if(!cbPath.isSelected() && tfDestination.getText()=="") {
	    		JOptionPane.showMessageDialog(null, "Destination path was not selected.\nChoose destination Path\nor check to override the orginal file");
	    	    return;
	    	}
	    	
	    	// read the salt and encrypted bytes from the input file
	    	byte[] salt = new byte[16];
	    	byte[] encryptedBytes;

	    	try (FileInputStream fis = new FileInputStream(inputFile)) {
	    	    fis.read(salt);
	    	    encryptedBytes = fis.readAllBytes();
	    	
	    	SecretKey secretKey=generateKey(password, salt);

	    	// initialize the cipher in decrypt mode with ECB mode
	    	Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	    	cipher.init(Cipher.DECRYPT_MODE, secretKey);

	    	// decrypt the encrypted bytes
	    	byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

	    	// write the decrypted bytes to a file
	    	
	    	File outputFile = new File(outputPath);
	    	FileOutputStream fos = new FileOutputStream(outputFile);
	    	fos.write(decryptedBytes);
	    	fos.close();

	    	lbSum2.setVisible(true);
	    	lbSum2.setText("After: "+checkSumm(outputPath));

	    	// display success message
	    	JOptionPane.showMessageDialog(null, "File decrypted successfully.");}
	    	catch (Exception e) {
	    		JOptionPane.showMessageDialog(null, "Decryption failed.");
	    	}

	    		
	        
	    }

	    @FXML
	    void onEncrypt(ActionEvent event) throws Exception {
	    	String filePath = tfPath.getText();
	    	String password = pfPass.getText();
	    	File inputFile = new File(filePath);
	    	
	    	

	    	// validate password and file path
	    	if (!validatePass(password)) {
	    	    JOptionPane.showMessageDialog(null, "Invalid password. Please try again.\nPassword must have at least one uppercase letter,\none lowercase letter, one digit,\nand one special character among @#$%^&+=, be 8-20 characters long, and contain no whitespace.");
	    	    return;
	    	}

	    	if (!inputFile.exists()) {
	    	    JOptionPane.showMessageDialog(null, "Invalid path. Please try again.");
	    	    return;
	    	}
	    	
	    	if(!cbPath.isSelected() && tfDestination.getText()=="") {
	    		JOptionPane.showMessageDialog(null, "Destination path was not selected.\nChoose destination Path\nor check to override the orginal file");
	    	    return;
	    	}
	    		
	    	
	    	lbSum1.setVisible(true);
	    	lbSum1.setText("Before: " + checkSumm(filePath));

	    	// perform encryption
	    	try {
	    	    // read the input file
	    	    byte[] inputBytes = Files.readAllBytes(inputFile.toPath());
	    	    
	    	    byte[] salt = new byte[16];
	    	    SecureRandom random = new SecureRandom();
	    	    random.nextBytes(salt);
	    	    
	    	    SecretKey secretKey=generateKey(password, salt);
	    	    
	    	    // initialize the cipher in encrypt mode with ECB mode
	    	    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	    	    cipher.init(Cipher.ENCRYPT_MODE, secretKey);

	    	    // encrypt the input bytes
	    	    byte[] encryptedBytes = cipher.doFinal(inputBytes);

	    	    // write the salt and encrypted bytes to a file
	    	    String outputPath = cbPath.isSelected() ? tfPath.getText() : tfDestination.getText();
	    	    File outputFile = new File(outputPath);
	    	    FileOutputStream fos = new FileOutputStream(outputFile);
	    	    fos.write(salt);
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
	    
	    private SecretKey generateKey(String key, byte[] salt) throws Exception {
	    	
    	    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    	    KeySpec spec = new PBEKeySpec(key.toCharArray(), salt, 10000, 256);
    	    SecretKey tmp = factory.generateSecret(spec);
    	    SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
    	    return secretKey;
	    }
	    
	    
	    
}
