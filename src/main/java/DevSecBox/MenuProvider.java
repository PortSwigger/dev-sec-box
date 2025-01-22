package DevSecBox;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import javax.swing.*;

public class MenuProvider implements ContextMenuItemsProvider {


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
                    requestResponseData.add(new Object[]{
                        requestResponse.request().httpService().host(), 
                        requestResponse.request().method(), 
                        requestResponse.request().url(), 
                        requestResponse.request().headers(),
                        requestResponse.request().body(), 
                        requestResponse.response().headers(), 
                        requestResponse.response().body()
                    });
                }
                Init.Core.WorkflowPanel.setLiveSwitchState(false);
                Init.Core.offlineReceiver(requestResponseData);
            });
            menuItemList.add(retrieveRequestResponseItem);
            return menuItemList;
        }
        return new ArrayList<>();
    }
}