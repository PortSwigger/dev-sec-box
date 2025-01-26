package DevSecBox;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.MontoyaApi;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutorService;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.swing.JMenuItem;

import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import java.awt.*;

public class Hook implements HttpHandler, ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final Core core;
    private final Map<Integer, Object[]> requestMap = new ConcurrentHashMap<>();
    private int currentRequestId = 1;
    private static final int MAX_REQUEST_ID = Integer.MAX_VALUE - 1;
    private static final ExecutorService executorService = Executors.newFixedThreadPool(1);
    private Map<String, String> replacements = getReplacements();
    List<String> nonModifiableContentTypes;
    public static volatile boolean isActive = true;

    public Hook(MontoyaApi api, Core core) {
        this.api = api;
        this.core = core;
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
            api.logging().logToOutput(Init.DSB + "default settings: " + ex.getMessage());
            nonModifiableContentTypes = List.of("image/", "application/octet-stream");
        }
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.isFromTool(ToolType.PROXY, ToolType.LOGGER)) {
            List<Component> menuItemList = new ArrayList<>();
            List<HttpRequestResponse> selectedRequestResponses = event.selectedRequestResponses();
            int totalCharacters = selectedRequestResponses.stream()
                    .mapToInt(
                            reqRes -> reqRes.request().toString().length() + reqRes.response().toString().length())
                    .sum();
            JMenuItem retrieveRequestResponseItem = new JMenuItem(
                    "pass raw prompt: ~" + Addons.formatSize(totalCharacters));
            retrieveRequestResponseItem.addActionListener(l -> {
                List<Object[]> requestResponseData = new ArrayList<>();
                for (HttpRequestResponse requestResponse : selectedRequestResponses) {
                    requestResponseData.add(new Object[] {
                            requestResponse.request().httpService().host(),
                            requestResponse.request().method(),
                            requestResponse.request().url(),
                            requestResponse.request().headers(),
                            requestResponse.request().body(),
                            requestResponse.response().headers(),
                            requestResponse.response().body(),
                            1
                    });
                }
                core.workflowPanel.setLiveSwitchState(false);
                core.offlineReceiver(requestResponseData);
            });
            menuItemList.add(retrieveRequestResponseItem);
            return menuItemList;
        }
        return new ArrayList<>();
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
                                .logToError(Init.DSB + "Invalid regex pattern: " + entry.getKey() + " - "
                                        + e.getMessage());
                    }
                }

                ByteArray modifiedBodyBytes = ByteArray.byteArray(modifiedBody.getBytes(StandardCharsets.UTF_8));
                HttpResponse modifiedResponse = httpResponseReceived.withBody(modifiedBodyBytes);

                List<Object[]> requestResponseData = new ArrayList<>();
                requestResponseData.add(requestData);
                core.onlineReceiver(requestResponseData);

                return ResponseReceivedAction.continueWith(modifiedResponse);
            }
        }

        return ResponseReceivedAction.continueWith(httpResponseReceived);
    }

    public static void Shutdown(MontoyaApi api) {
        if (Hook.isActive) {
            if (executorService != null) {
                executorService.shutdownNow();
                try {
                    if (!executorService.awaitTermination(60, TimeUnit.SECONDS)) {
                        api.logging()
                                .logToError(Init.DSB + "executor did not terminate in the specified time.");
                    }
                } catch (InterruptedException e) {
                    api.logging().logToError(Init.DSB + "termination interrupted: " + e.getMessage());
                    Thread.currentThread().interrupt();
                }
            }

            isActive = false;
            Issue.liveIssueOFF();
            if (Linker.processSemaphore.availablePermits() == 0) {
                Linker.processSemaphore.release();
            }
            if (Linker.Scheduler != null) {
                Linker.Scheduler.shutdownNow();
                try {
                    if (!Linker.Scheduler.awaitTermination(60, TimeUnit.SECONDS)) {
                        api.logging().logToError(
                                Init.DSB + "scheduler did not terminate in the specified time.");
                    }
                } catch (InterruptedException e) {
                    api.logging()
                            .logToError(Init.DSB + "scheduler termination interrupted: " + e.getMessage());
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public static void Start() {
        if (!Hook.isActive) {
            isActive = true;
        }
    }
}