/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

package pt.webdetails.browserid;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;

import org.json.JSONException;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;

/**
 * Simple client for a BrowserID verify call.
 */
public class BrowserIdVerifier {

  private static String DEFAULT_VERIFY_URL = "https://browserid.org/verify";
  private static final String ENCODING = "UTF-8";
  
  private String url = DEFAULT_VERIFY_URL;
  private ResponseHandler<BrowserIdResponse> responseHandler;
  private HttpClient client;
  
  /**
   * 
   * @param verifyUrl The URL that performs the verification. Defaults to <code>https://browserid.org/verify</code>.
   */
  public BrowserIdVerifier(String verifyUrl){
    verifyUrl = StringUtils.trim(verifyUrl);
    this.url = StringUtils.isEmpty(verifyUrl) ?  DEFAULT_VERIFY_URL : verifyUrl;
    this.responseHandler = new BrowserIdResponseHandler();
    this.client = getNewHttpClient();
  }
  
  public BrowserIdVerifier(){
    this(null);
  }
  
  /**
   * 
   * @return The URL this verifier is using.
   */
  public String getVerifyUrl(){
    return url;
  }
  
  /**
   * Verify if the given assertion is valid
   * @param assertion The assertion as returned 
   * @param audience
   * @return
   * @throws HttpException if an HTTP protocol exception occurs or the service returns a code not in the 200 range.
   * @throws IOException if a transport error occurs.
   * @throws JSONException if the result cannot be parsed as JSON markup
   */
  public BrowserIdResponse verify(String assertion, String audience) throws HttpException, IOException {
       
    HttpPost post = getPostMethod(url, assertion, audience);
    return client.execute(post, responseHandler);
  }
  
  private boolean isHttps(final String url){
    return StringUtils.indexOf(url, "https://") == 0;
  }
  
  private HttpClient getNewHttpClient(){
    HttpClient client = new DefaultHttpClient();
    //force hostname verification
    SSLSocketFactory socketFactory;
    try {
      SSLContext context = SSLContext.getInstance(SSLSocketFactory.TLS);
      //nulls here will use defaults
      context.init(null, null, null); 
      socketFactory =new SSLSocketFactory(context, SSLSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    } catch (KeyManagementException e) {
      throw new RuntimeException(e);
    }
    Scheme httpsStrict = new Scheme("https", 443, socketFactory);
    client.getConnectionManager().getSchemeRegistry().register(httpsStrict);
    return client;
  }
  
  private HttpPost getPostMethod(String url, String assertion, String audience){
    
    if(!isHttps(url)) {
      throw new IllegalArgumentException("only https is supported");
    }
    try {
      String postUrl = url + "?assertion=" + URLEncoder.encode(assertion, ENCODING) + "&audience=" +  URLEncoder.encode(audience, ENCODING) ;
      HttpPost post = new HttpPost(postUrl);
      return post;
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }
 
  private static class BrowserIdResponseHandler implements ResponseHandler<BrowserIdResponse> {

    private static boolean isHttpResponseOK(int statusCode){
      return statusCode >= 200 && statusCode < 300;
    }
    
    @Override
    public BrowserIdResponse handleResponse(HttpResponse response) throws IOException {
      if(isHttpResponseOK(response.getStatusLine().getStatusCode())){
        try{
          return new BrowserIdResponse( IOUtils.toString(response.getEntity().getContent()));
        }
        catch (JSONException e){
          throw new ClientProtocolException("Unparseable response", e);
        }
      }
      else throw new ClientProtocolException("HTTP Response not OK: " + response.getStatusLine().toString());
    }
    
  }
  
}
