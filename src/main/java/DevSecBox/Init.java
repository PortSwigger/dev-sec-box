package DevSecBox;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.MontoyaApi;

public class Init implements BurpExtension {
    public static String DSB = "□─■ DevSecBox ";
    public static final OS CURRENTOS = detectOS();
    private MontoyaApi api;
    private Core core;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("DevSecBox");
        api.extension().registerUnloadingHandler(new DSBUnloadingHandler());

        switch (CURRENTOS) {
            case MAC:
                api.logging().logToOutput("                   ┏━━━━┓");
                api.logging().logToOutput("□─■ Level up with DevSec┃ for macOS https://github.com/taradaidv/");
                api.logging().logToOutput("                   ┗━━━━┛");
                break;
            case WINDOWS:
                api.logging().logToOutput("□─■ HuntTheBox with DevSecBox for Windows https://github.com/taradaidv/");
                break;
            case LINUX:
                api.logging().logToOutput("□─■ DevSecOps with DevSecBox for Linux https://github.com/taradaidv/");
                break;
            default:
                api.logging().logToOutput("□─■ Level up with DevSecBox https://github.com/taradaidv/");
                break;
        }

        core = new Core(api);
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
            if (api != null) {
                api.logging().logToOutput(DSB + "API is initialized");
            } else {
                api.logging().logToOutput(DSB + "API is null");
            }
            if (core != null) {
                api.logging().logToOutput(DSB + "core is initialized");
            } else {
                api.logging().logToOutput(DSB + "core is null");
            }
            if (core != null) {
                try {
                    api.logging().logToOutput(DSB + "attempting to clear workflow panel components");
                    core.workflowPanel.clearAllComponents();
                    api.logging().logToOutput(DSB + "workflow panel components cleared successfully");
                } catch (Exception e) {
                    api.logging()
                            .logToError(DSB + "error clearing workflow panel components: " + e.getMessage());
                    e.printStackTrace();
                }
                core = null;
                api.logging().logToOutput(DSB + "core reference set to null");
            }

            if (core == null) {
                api.logging().logToOutput(DSB + "orchestrator stopped and unloaded successfully");
            } else {
                api.logging().logToError(DSB + "failed to unload orchestrator, core is not null");
            }
        }
    }
}