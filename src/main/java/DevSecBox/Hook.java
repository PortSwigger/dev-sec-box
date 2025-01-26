package DevSecBox;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.MontoyaApi;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class Hook implements HttpHandler {
    private final MontoyaApi api;
    private final Map<Integer, Object[]> requestMap = new ConcurrentHashMap<>();
    private int currentRequestId = 1;
    private static final int MAX_REQUEST_ID = Integer.MAX_VALUE - 1;
    private static final ExecutorService executorService = Executors.newFixedThreadPool(1);
    private Map<String, String> replacements = getReplacements();
    List<String> nonModifiableContentTypes;
    public static volatile boolean isActive = true;

    public Hook(MontoyaApi api) {
        this.api = api;
        loadConfiguration();
    }

    private Map<String, String> getReplacements() {
        return Linker.spoofMap;
    }

    private void loadConfiguration() {
        Properties properties = new Properties();
        try (InputStream input = getClass().getClassLoader().getResourceAsStream("config.properties")) {
            if (input == null) {
                throw new IOException("pre-configured types");
            }
            properties.load(input);
            String types = properties.getProperty("nonModifiableContentTypes", "");
            nonModifiableContentTypes = Arrays.asList(types.split(","));
        } catch (IOException ex) {
            api.logging().logToOutput(Init.PREF + Init.DSB + "default settings: " + ex.getMessage());
            nonModifiableContentTypes = List.of("image/", "application/octet-stream");
        }
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        if (!isActive || Issue.liveIssue) {
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }

        if (currentRequestId > MAX_REQUEST_ID) {
            currentRequestId = 1;
        }
        int requestId = currentRequestId++;
        Object[] requestData = new Object[8];
        requestData[0] = httpRequestToBeSent.httpService().host();
        requestData[1] = httpRequestToBeSent.method();
        requestData[2] = httpRequestToBeSent.url();
        requestData[3] = httpRequestToBeSent.headers();
        requestData[4] = httpRequestToBeSent.body();
        requestData[7] = requestId;
        requestMap.put(requestId, requestData);
        return RequestToBeSentAction.continueWith(httpRequestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        if (!isActive || Issue.liveIssue) {
            return ResponseReceivedAction.continueWith(httpResponseReceived);
        }

        Object[] requestData = null;

        for (Map.Entry<Integer, Object[]> entry : requestMap.entrySet()) {
            requestData = entry.getValue();
            if (requestData != null) {
                requestMap.remove(entry.getKey());
                break;
            }
        }

        if (requestData != null) {
            requestData[5] = httpResponseReceived.headers();
            requestData[6] = httpResponseReceived.body();

            String contentType = httpResponseReceived.headers().stream()
                    .filter(header -> header.name().equalsIgnoreCase("Content-Type"))
                    .map(HttpHeader::value)
                    .findFirst()
                    .orElse("");

            boolean shouldModify = nonModifiableContentTypes.stream().noneMatch(contentType::startsWith);

            if (shouldModify) {
                String originalBody = new String(httpResponseReceived.body().getBytes(), StandardCharsets.UTF_8);

                String modifiedBody = originalBody;
                for (Map.Entry<String, String> entry : replacements.entrySet()) {
                    try {
                        Pattern pattern = Pattern.compile(entry.getKey(), Pattern.CASE_INSENSITIVE);
                        Matcher matcher = pattern.matcher(modifiedBody);
                        modifiedBody = matcher.replaceAll(entry.getValue());
                    } catch (PatternSyntaxException e) {
                        api.logging()
                                .logToError(Init.PREF + Init.DSB + "Invalid regex pattern: " + entry.getKey() + " - "
                                        + e.getMessage());
                    }
                }

                ByteArray modifiedBodyBytes = ByteArray.byteArray(modifiedBody.getBytes(StandardCharsets.UTF_8));
                HttpResponse modifiedResponse = httpResponseReceived.withBody(modifiedBodyBytes);

                List<Object[]> requestResponseData = new ArrayList<>();
                requestResponseData.add(requestData);
                Init.Core.onlineReceiver(requestResponseData);

                return ResponseReceivedAction.continueWith(modifiedResponse);
            }
        }

        return ResponseReceivedAction.continueWith(httpResponseReceived);
    }

    public static void Shutdown() {
        if (Hook.isActive) {
            if (executorService != null) {
                executorService.shutdownNow();
            }
            isActive = false;
            Issue.liveIssueOFF();
            Linker.processSemaphore.release();
            Linker.Scheduler.shutdownNow();
        }
    }

    public static void Start() {
        if (!Hook.isActive) {
            isActive = true;
        }
    }
}