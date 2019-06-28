import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.lang.StringUtils;

public class DeliveryReportTimeRange {
	
	private final static String USER_AGENT = "Mozilla/5.0";
	private final static String SIGNATURE_PARAMETERS = "signature";
	private final static String ENCODING_STANDARD_FORMAT = "UTF-8";
	private final static DateFormat iso8601UtcTimeFormatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
	private static final String HEX = "0123456789ABCDEF";
	private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
	
	public static void main(String[] args) throws IOException {
		String clientId = "YOUR-CLIENT-ID";
		String appType = "YOUR-APP-TYPE";
		String mediaType = "YOUR-MEDIA-TYPE";
		String requestDate = "2019-06-28";
		String startTime = "12:40:00";
		String endTime = "12:50:00";
		String timeStamp = printIso8601Utc();
		
		Map<String, String> paramMap = new HashMap<String, String>();
		paramMap.put("clientId", clientId);
		paramMap.put("appType",appType);
		paramMap.put("mediaType",mediaType);
		paramMap.put("requestDate", requestDate);
		paramMap.put("startTime", startTime);
		paramMap.put("endTime", endTime);
		paramMap.put("timestamp",timeStamp);
		
		String signature = getExpectedSignature("YOUR-PRIVATE-KEY", paramMap);
		
		@SuppressWarnings("deprecation")
		String url = "https://otpm-report.kokatto.com/otpm/report?clientId=" + clientId + "&appType=" + appType + "&mediaType=" + mediaType 
				+ "&timestamp=" + URLEncoder.encode(timeStamp) 
				+ "&requestDate=" + requestDate + "&startTime=" + startTime + "&endTime=" + endTime 
				+ "&signature=" + signature;
		URL obj = new URL(url);
		HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
		
		// optional default is GET
		con.setRequestMethod("GET");

		//add request header
		con.setRequestProperty("User-Agent", USER_AGENT);

		int responseCode = con.getResponseCode();
		System.out.println("\nSending 'GET' request to URL : " + url);
		System.out.println("Response Code : " + responseCode);

		BufferedReader in = new BufferedReader(
		        new InputStreamReader(con.getInputStream()));
		String inputLine;
		StringBuffer response = new StringBuffer();

		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		in.close();

		//print result
		System.out.println(response.toString());
	}
	
	public static String getExpectedSignature(String privateKey, Map<String, String> requestParam) {
		
		String queryParameters = constructQueryParameters(requestParam);
		
		String expectedSignature = "";
		
		try {
			expectedSignature = URLEncoder.encode(
					calculateRFC2104HMACSHA256(
							MD5HashStandard(queryParameters), 
							privateKey
						), ENCODING_STANDARD_FORMAT);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return expectedSignature;
	}
	
	public static String calculateRFC2104HMACSHA256(String data, String key) throws java.security.SignatureException {
		String result;
		
		try {
			SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA256_ALGORITHM);

			Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
			mac.init(signingKey);

			byte[] rawHmac = mac.doFinal(data.getBytes());

			result = toHex(rawHmac);
		} catch (Exception e){
			throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
		}
		
		return result;
	}
	
	public static String MD5HashStandard(String input){
		return hashStr(input, "MD5");
	}
	
	private static String constructQueryParameters(Map<String, String> paramMap){
		List<String> queryStringList = new ArrayList<String>();
		for (Entry<String, String> param : paramMap.entrySet()){
			if (!param.getKey().equalsIgnoreCase(SIGNATURE_PARAMETERS)){
				
				try {
					queryStringList.add(param.getKey()+"="+URLEncoder.encode(param.getValue(), ENCODING_STANDARD_FORMAT));
				} catch (UnsupportedEncodingException e) {
					e.printStackTrace();
				}
			}
		}
		
		Collections.sort(queryStringList);
		
		return queryStringList != null && queryStringList.size() > 0 ? StringUtils.join(queryStringList, "&") : "";
		
	}
	
	public static String printIso8601Utc() {
		return iso8601UtcTimeFormatter.format(new Date());
	}
	
	public static String toHex(byte[] stringBytes)
    {
        StringBuffer result = new StringBuffer(2*stringBytes.length);
         
        for (int i = 0; i < stringBytes.length; i++) {
            result.append(HEX.charAt((stringBytes[i]>>4)&0x0f)).append(HEX.charAt(stringBytes[i]&0x0f));
        }
         
        return result.toString();
    }
	
	private static String hashStr(String inStr, String algorithm)
	{
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm);
			byte[] inByte = inStr.getBytes();
			byte[] outByte = md.digest(inByte);

			StringBuffer sb = new StringBuffer();

        		for (int i = 0; i < outByte.length; ++i) {
				sb.append(Integer.toHexString((outByte[i] & 0xFF) | 0x100).substring(1,3));
			}

			return sb.toString();

		} catch (NoSuchAlgorithmException nsae){ System.out.println("Invalid algorithm specified"); }

		return "";
	}
}
