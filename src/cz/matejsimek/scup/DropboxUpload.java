package cz.matejsimek.scup;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.CCMParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.MultipartEntity;
import org.apache.http.entity.mime.content.ContentBody;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.CoreProtocolPNames;
import org.apache.http.entity.mime.content.ByteArrayBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.util.EntityUtils;

/**
 * Dropbox file uploading based on Dropbox SDK (but hacked to do e.3d3.ca)
 *
 * @author Matej Simek | www.matejsimek.cz (but not really)
 */
public class DropboxUpload {

  final static private int MacSize = 64;
  final static private String PrivKey = "c61540b5ceecd05092799f936e27755f";
  final static private String SystemUrl = "https://e.3d3.ca";



  /**
   * Invokes connection to Dropbox API
   *
   * @param key User API token key
   * @param secret User API token secret
   * @throws DropboxException
   */
  public DropboxUpload() {
  }
  
  private static int findIVLen(int length) {
    if (length < 0xFFFF) return 15 - 2;
    if (length < 0xFFFFFF) return 15 - 3;
    return 15 - 4;
  }

  /**
   * Uploads given file to Dropbox, handles unlink exception with new
   * authentication
   *
   * @param file file to upload
   * @param fileName name of file on Dropbox
   * @return
   */
  public String uploadFile(File file, String fileName) throws FileNotFoundException, IOException, InvalidCipherTextException {
      
    // Do all of the crypto stuff
    SecureRandom sr = new SecureRandom();
    
    byte[] seed = new byte[16];
    sr.nextBytes(seed);
    
    String seedString = Base64.encodeBase64URLSafeString(seed);
    
    SHA512Digest dg = new SHA512Digest();
    dg.update(seed, 0, seed.length);
    
    byte[] seedResult = new byte[64];
    dg.doFinal(seedResult, 0);
    
    //byte[] key = Arrays.copyOfRange(seedResult, 0, 32);
    byte[] iv = Arrays.copyOfRange(seedResult, 32, 48);
    byte[] ident = Arrays.copyOfRange(seedResult, 48, 64);
    String identString = Base64.encodeBase64URLSafeString(ident);
    
    KeyParameter keyParam = new KeyParameter(seedResult, 0, 32);
    
    byte[] fdata = IOUtils.toByteArray(new FileInputStream(file));
    
    byte[] civ = Arrays.copyOf(iv, findIVLen(fdata.length));
    CCMParameters ccmParam = new CCMParameters(keyParam, MacSize, civ, new byte[0]);
    CCMBlockCipher ccmCipher = new CCMBlockCipher(new AESFastEngine());
    ccmCipher.init(true, ccmParam);
    
    byte[] ct = new byte[ccmCipher.getOutputSize(fdata.length)];
    ccmCipher.processBytes(fdata, 0, fdata.length, ct, 0);
    ccmCipher.doFinal(ct, 0);
    
    
    // Do all of the upload stuff
    HttpClient hc = new DefaultHttpClient();
    hc.getParams().setParameter(CoreProtocolPNames.PROTOCOL_VERSION, HttpVersion.HTTP_1_1);
    
    HttpPost hp = new HttpPost(SystemUrl + "/up");
    
    MultipartEntity mpEntity = new MultipartEntity();
    ContentBody cbBlob = new ByteArrayBody(ct, "blob");
    mpEntity.addPart("file", cbBlob);
    ContentBody cbIdent = new StringBody(identString);
    mpEntity.addPart("ident", cbIdent);
    ContentBody cbPrivKey = new StringBody(PrivKey);
    mpEntity.addPart("privkey", cbPrivKey);
    
    hp.setEntity(mpEntity);
    System.out.println("executing request " + hp.getRequestLine());
    HttpResponse hr = hc.execute(hp);
    HttpEntity resEntity = hr.getEntity();
    
    System.out.println(hr.getStatusLine());
    
    if (resEntity != null) {
        System.out.println("Data: " + EntityUtils.toString(resEntity));
    }
    
    if (resEntity != null) {
        resEntity.consumeContent();
    }
    
    hc.getConnectionManager().shutdown();
    
    return SystemUrl + "/#/" + seedString + "?d";
  }
}
