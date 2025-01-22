package DevSecBox;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.MontoyaApi;

public class Init implements BurpExtension {
    public static String DSB = "DevSecBox ";
    public static String PREF = "□─■ ";
    private Logging logging;
    private Hook Hook;
    public static final OS CURRENTOS = detectOS();
    public static MontoyaApi api;
    public static Core Core;

    @Override
    public void initialize(MontoyaApi api) {
        Init.api = api;
        api.extension().setName("DevSecBox");
        Extension extension = api.extension();
        extension.registerUnloadingHandler(new DSBUnloadingHandler());
        logging = api.logging();

        switch (CURRENTOS) {
            case MAC:
                logging.logToOutput("                   ┏━━━━┓");
                logging.logToOutput(PREF + "Level up with DevSec┃ for macOS https://github.com/taradaidv/");
                logging.logToOutput("                   ┗━━━━┛");
                break;
            case WINDOWS:
                logging.logToOutput(PREF + "HuntTheBox with DevSecBox for Windows https://github.com/taradaidv/");
                break;
            case LINUX:
                logging.logToOutput(PREF + "DevSecOps with DevSecBox for Linux https://github.com/taradaidv/");
                break;
            default:
                logging.logToOutput(PREF + "Level up with DevSecBox https://github.com/taradaidv/");
                break;
        }

        Core = new Core();
        Hook = new Hook();
        Hook.initialize(Init.api);
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

    public class DSBUnloadingHandler implements ExtensionUnloadingHandler {
        @Override
        public void extensionUnloaded() {
            Core.WorkflowPanel.clearAllComponents();
            logging.logToOutput(PREF + DSB + "orchestrator unloaded - LIVE HOOK ");
            logging.logToOutput(PREF + DSB + "orchestrator unloaded - PROXY/LOGGER");
            logging.logToOutput(PREF + DSB + "extension was unloaded.");
        }
    }

    public enum OS {
        MAC, WINDOWS, LINUX, UNKNOWN
    }
}