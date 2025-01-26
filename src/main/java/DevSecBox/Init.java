package DevSecBox;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.MontoyaApi;

public class Init implements BurpExtension {
    public static String DSB = "DevSecBox ";
    public static String PREF = "□─■ ";
    public static final OS CURRENTOS = detectOS();
    private MontoyaApi api;
    public static Core Core;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("DevSecBox");
        api.extension().registerUnloadingHandler(new DSBUnloadingHandler());

        switch (CURRENTOS) {
            case MAC:
                api.logging().logToOutput("                   ┏━━━━┓");
                api.logging().logToOutput(PREF + "Level up with DevSec┃ for macOS https://github.com/taradaidv/");
                api.logging().logToOutput("                   ┗━━━━┛");
                break;
            case WINDOWS:
                api.logging().logToOutput(PREF + "HuntTheBox with DevSecBox for Windows https://github.com/taradaidv/");
                break;
            case LINUX:
                api.logging().logToOutput(PREF + "DevSecOps with DevSecBox for Linux https://github.com/taradaidv/");
                break;
            default:
                api.logging().logToOutput(PREF + "Level up with DevSecBox https://github.com/taradaidv/");
                break;
        }

        Core = new Core(api);
        api.logging().logToOutput(PREF + DSB + "orchestrator loaded and running");
    }

    private static OS detectOS() {
        String osName = System.getProperty("os.name").toLowerCase();
        if (osName.contains("mac")) {
            return OS.MAC;
        } else if (osName.contains("win")) {
            return OS.WINDOWS;
        } else if (osName.contains("nux") || osName.contains("nix")) {
            return OS.LINUX;
        } else {
            return OS.UNKNOWN;
        }
    }

    public enum OS {
        MAC, WINDOWS, LINUX, UNKNOWN
    }

    public class DSBUnloadingHandler implements ExtensionUnloadingHandler {
        @Override
        public void extensionUnloaded() {
            Core.workflowPanel.clearAllComponents();
            api.logging().logToOutput(PREF + DSB + "orchestrator stopped and unloaded");
        }
    }
}