package DevSecBox;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.MontoyaApi;
import java.io.InputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

public class Init implements BurpExtension {
    public static String DSB = "DevSecBox ";
    public static String PREF = "□─■ ";
    public static Logging logging;
    private Hook hook; 
    public static final OS CURRENTOS = detectOS();
    public static MontoyaApi api;
    public static Core Core;

    @Override
    public void initialize(MontoyaApi api) {
        Init.api = api;
        logging = api.logging();
        api.extension().setName("DevSecBox");
        Extension extension = api.extension();
        extension.registerUnloadingHandler(new DSBUnloadingHandler());

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
        hook = new Hook();
        Hook.Start();
        logging.logToOutput(PREF + DSB + "orchestrator loaded and running");
        loadConfiguration();
        api.http().registerHttpHandler(hook);
    }

    private void loadConfiguration() {
        Properties properties = new Properties();
        try (InputStream input = getClass().getClassLoader().getResourceAsStream("config.properties")) {
            if (input == null) {
                throw new IOException("pre-configured types");
            }
            properties.load(input);
            String types = properties.getProperty("nonModifiableContentTypes", "");
            hook.nonModifiableContentTypes = Arrays.asList(types.split(","));
        } catch (IOException ex) {
            logging.logToOutput(PREF + DSB + "default settings: " + ex.getMessage());
            hook.nonModifiableContentTypes = List.of("image/", "application/octet-stream");
        }
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
            Core.WorkflowPanel.clearAllComponents();
            logging.logToOutput(PREF + DSB + "orchestrator stopped and unloaded");
        }
    }
}