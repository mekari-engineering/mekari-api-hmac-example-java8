package id.mkr.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.UUID;

import okhttp3.Call;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class HmacGeneratorApplication {
    public static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

    public static void main(String[] args) {

        OkHttpClient client = new OkHttpClient();

        //      Request Base URL
        String base = "https://api-sandbox-sso.mekari.com";

        //      HMAC User client id
        String clientId = System.getenv("MEKARI_API_CLIENT_ID");

        //      HMAC User client secret
        String clientSecret = System.getenv("MEKARI_API_CLIENT_SECRET");

        //      Request method GET/POST/PUT/DELETE
        String method = "POST";

        //      Request endpoint
        String path = "/v2/klikpajak/v1/efaktur/out";
        String queryParam = "?auto_approval=false";


        //      Request Body
        String json = "{\n" +
            "    \"client_reference_id\": \"INVOICE01\",\n" +
            "    \"transaction_detail\": \"01\",\n" +
            "    \"additional_trx_detail\": \"00\",\n" +
            "    \"substitution_flag\": false,\n" +
            "    \"document_date\": \"2021-09-02\",\n" +
            "    \"reference\": \"test\",\n" +
            "    \"customer\": {\n" +
            "        \"name\": \"John\",\n" +
            "        \"npwp\": \"711033282416009\",\n" +
            "        \"nik\": \"0000000000000000\",\n" +
            "        \"address\": \"home\",\n" +
            "        \"email\": \"john@email.com\"\n" +
            "    },\n" +
            "    \"items\": [\n" +
            "        {\n" +
            "            \"name\": \"pen\",\n" +
            "            \"unit_price\": 10000.12345,\n" +
            "            \"quantity\": 20.12345,\n" +
            "            \"discount\": 10,\n" +
            "            \"ppnbm_rate\": 0.001\n" +
            "        },\n" +
            "        {\n" +
            "            \"name\": \"eraser\",\n" +
            "            \"unit_price\": 10000.12345,\n" +
            "            \"quantity\": 20.12345,\n" +
            "            \"discount\": 10,\n" +
            "            \"ppnbm_rate\": 0.001\n" +
            "        }\n" +
            "    ]\n" +
            "}";

        RequestBody body = RequestBody.create(json, JSON); // new
        Request request = new Request.Builder()
            .url(base + path + queryParam)
            .post(body)
            .addHeader("Date", getDateTimeNowUtcString())
            .addHeader("Authorization",
                generateAuthSignature(clientId, clientSecret, method, path + queryParam, getDateTimeNowUtcString())
            )
            .addHeader("x-idempotency-key", UUID.randomUUID().toString())
            .build();

        Call call = client.newCall(request);
        try {
            Response response = call.execute();
            System.out.println(response.body().string());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String generateAuthSignature(
        String clientId, String clientSecret, String method,
        String pathWithQueryParam, String dateString
    ) {
        String payload = generatePayload(pathWithQueryParam, method, dateString);
        String signature = hmacSha256(clientSecret, payload);

        return "hmac username=\"" + clientId
            + "\", algorithm=\"hmac-sha256\", headers=\"date request-line\", signature=\""
            + signature + "\"";
    }

    private static String generatePayload(String pathWithQueryParam, String method, String dateString) {
        String requestLine = method + ' ' + pathWithQueryParam + " HTTP/1.1";
        return String.join("\n", Arrays.asList("date: " + dateString, requestLine));
    }

    private static String hmacSha256(String clientSecret, String payload) {
        try {
            SecretKeySpec signingKey = new SecretKeySpec(clientSecret.getBytes("UTF-8"), "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(signingKey);

            return Base64.getEncoder().encodeToString(mac.doFinal(payload.getBytes("UTF-8")));
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException | InvalidKeyException exception) {
            exception.printStackTrace();
            return null;
        }
    }

    private static String getDateTimeNowUtcString() {
        Instant instant = Instant.now();
        return DateTimeFormatter.RFC_1123_DATE_TIME
            .withZone(ZoneOffset.UTC)
            .withLocale(Locale.US)
            .format(instant);
    }
}
